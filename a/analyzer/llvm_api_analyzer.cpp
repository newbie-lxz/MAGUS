#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace llvm;
namespace fs = std::filesystem;

namespace {

// 1. CLI 参数与核心运行状态
cl::opt<std::string> ProjectId("project-id", cl::Required, cl::desc("Project identifier"));
cl::opt<std::string> RepoPath("repo-path", cl::Required, cl::desc("Repository root"));
cl::opt<std::string> OutputRoot("output-root", cl::Required, cl::desc("DFA output root"));
cl::opt<std::string> BitcodeList("bc-list", cl::Required, cl::desc("Path to bc.list"));
cl::opt<std::string> SinkConfig("sink-config", cl::Required, cl::desc("Path to sink taxonomy JSON"));

struct SinkRuleSet {
    // 单类 sink 的 exact/prefix/contains 匹配规则。
    std::string kind;
    std::set<std::string> exact;
    std::vector<std::string> prefix;
    std::vector<std::string> contains;
};

struct SourceLocation {
    // 解析后的源码位置，优先使用 debug info。
    std::string file;
    unsigned line = 0;
};

struct APIPath {
    // 分析过程中构造的 API/检查节点，也是最终 JSON path 图的基本单元。
    std::string name;
    std::string address;
    std::set<int> parameter;
    std::string file;
    unsigned line = 0;
    std::string sinkKind;
    std::string callKind;
    bool unresolvedIndirect = false;
    std::vector<std::string> resolvedCallees;
    std::string checkKind;
    std::string conditionText;
    unsigned branchCount = 0;
    size_t order = std::numeric_limits<size_t>::max();
    size_t serial = std::numeric_limits<size_t>::max();
    std::set<APIPath *> prev;
    std::set<APIPath *> next;
};

struct AnalyzerContext {
    // 跨模块共享的只读配置与输出路径。
    std::string projectId;
    fs::path repoRoot;
    fs::path outputRoot;
    fs::path timeoutLog;
    std::vector<SinkRuleSet> sinkRules;
    size_t maxCrossFunctionDepth = 5;
    std::unordered_set<std::string> helperBlacklistExact;
    std::vector<std::string> helperBlacklistPrefix;
};

struct RootAnalysisState {
    // 以单个 root call 为粒度的运行时状态和统计信息。
    std::string fileName;
    std::string functionName;
    std::string apiName;
    std::clock_t fileStartTime = 0;
    std::clock_t functionStartTime = 0;
    std::clock_t instructionStartTime = 0;
    bool timedOut = false;
    size_t nodeCount = 0;
    size_t nextSerial = 0;
    size_t resolvedIndirectCallSites = 0;
    size_t unresolvedIndirectCallSites = 0;
    size_t indirectCandidateCapHitSites = 0;
    bool crossFunctionBudgetHit = false;
    std::vector<const Function *> expansionStack;
    std::set<std::string> warnings;
};

struct ResolvedCallTargets {
    // 对 direct/indirect call 的目标函数解析结果。
    std::vector<Function *> callees;
    bool isIndirect = false;
    bool unresolved = false;
    bool candidateCapHit = false;
};

struct CalleeSummary {
    // 跨函数展开时，从 callee 回传给 caller 的摘要信息。
    std::set<int> returnTags;
    std::map<unsigned, std::set<int>> pointerArgumentTags;
    std::map<Value *, std::set<int>> globalTags;
};

using RelateMap = std::map<Value *, std::set<int>>;
using VisitMap = std::map<BasicBlock *, std::pair<APIPath *, APIPath *>>;
using OrderMap = std::unordered_map<Instruction *, size_t>;
using FunctionOrderMap = std::unordered_map<const Function *, OrderMap>;

// 2. 通用字符串、配置与路径辅助函数
std::string trim(const std::string &value) {
    size_t begin = 0;
    size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::string toLowerCopy(const std::string &value) {
    std::string lowered = value;
    std::transform(
        lowered.begin(),
        lowered.end(),
        lowered.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
    );
    return lowered;
}

Expected<std::vector<SinkRuleSet>> loadSinkTaxonomy(const fs::path &path) {
    // 读取与 Python 侧共享的 sink taxonomy，保持分类口径一致。
    ErrorOr<std::unique_ptr<MemoryBuffer>> buffer = MemoryBuffer::getFile(path.generic_string());
    if (!buffer) {
        return createStringError(inconvertibleErrorCode(), "failed to read sink taxonomy: %s", path.c_str());
    }

    Expected<json::Value> parsed = json::parse(buffer.get()->getBuffer());
    if (!parsed) {
        return createStringError(inconvertibleErrorCode(), "failed to parse sink taxonomy JSON: %s", path.c_str());
    }

    json::Object *root = parsed->getAsObject();
    if (root == nullptr) {
        return createStringError(inconvertibleErrorCode(), "sink taxonomy root must be an object");
    }

    json::Array *categories = root->getArray("categories");
    if (categories == nullptr || categories->empty()) {
        return createStringError(inconvertibleErrorCode(), "sink taxonomy must contain a non-empty categories array");
    }

    std::vector<SinkRuleSet> rules;
    for (size_t index = 0; index < categories->size(); ++index) {
        json::Object *entry = (*categories)[index].getAsObject();
        if (entry == nullptr) {
            return createStringError(inconvertibleErrorCode(), "sink taxonomy category %zu must be an object", index);
        }

        std::optional<StringRef> kind = entry->getString("kind");
        if (!kind || kind->trim().empty()) {
            return createStringError(inconvertibleErrorCode(), "sink taxonomy category %zu is missing kind", index);
        }

        SinkRuleSet rule;
        rule.kind = toLowerCopy(kind->trim().str());

        auto loadStrings = [&](const char *fieldName, std::set<std::string> *targetSet, std::vector<std::string> *targetList) -> Error {
            json::Array *items = entry->getArray(fieldName);
            if (items == nullptr) {
                return Error::success();
            }
            for (const json::Value &item : *items) {
                std::optional<StringRef> text = item.getAsString();
                if (!text) {
                    return createStringError(inconvertibleErrorCode(), "sink taxonomy field %s must contain only strings", fieldName);
                }
                const std::string normalized = toLowerCopy(text->trim().str());
                if (normalized.empty()) {
                    continue;
                }
                if (targetSet != nullptr) {
                    targetSet->insert(normalized);
                }
                if (targetList != nullptr) {
                    targetList->push_back(normalized);
                }
            }
            return Error::success();
        };

        if (Error error = loadStrings("exact", &rule.exact, nullptr)) {
            return std::move(error);
        }
        if (Error error = loadStrings("prefix", nullptr, &rule.prefix)) {
            return std::move(error);
        }
        if (Error error = loadStrings("contains", nullptr, &rule.contains)) {
            return std::move(error);
        }

        rules.push_back(std::move(rule));
    }

    return rules;
}

std::vector<std::string> readBitcodePaths(const fs::path &path) {
    // 读取 bc.list，保留非空 bitcode 路径。
    std::ifstream handle(path);
    std::vector<std::string> results;
    std::string line;
    while (std::getline(handle, line)) {
        line = trim(line);
        if (!line.empty()) {
            results.push_back(line);
        }
    }
    return results;
}

std::string jsonEscape(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\b':
                escaped += "\\b";
                break;
            case '\f':
                escaped += "\\f";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    char buffer[7];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
                    escaped += buffer;
                } else {
                    escaped.push_back(static_cast<char>(ch));
                }
        }
    }
    return escaped;
}

std::string sanitizeBucketName(const std::string &name) {
    std::string sanitized;
    sanitized.reserve(name.size());
    for (unsigned char ch : name) {
        if (std::isalnum(ch) || ch == '_' || ch == '.' || ch == '-') {
            sanitized.push_back(static_cast<char>(ch));
        } else {
            sanitized.push_back('_');
        }
    }
    while (!sanitized.empty() && (sanitized.front() == '.' || sanitized.front() == '_')) {
        sanitized.erase(sanitized.begin());
    }
    while (!sanitized.empty() && (sanitized.back() == '.' || sanitized.back() == '_')) {
        sanitized.pop_back();
    }
    return sanitized.empty() ? "unknown_api" : sanitized;
}

size_t parsePositiveEnvOrDefault(const char *name, size_t fallback) {
    const char *raw = std::getenv(name);
    if (raw == nullptr) {
        return fallback;
    }

    const std::string text = trim(raw);
    if (text.empty()) {
        return fallback;
    }

    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
    if (end == text.c_str() || (end != nullptr && *end != '\0') || parsed == 0) {
        return fallback;
    }
    return static_cast<size_t>(parsed);
}

std::vector<std::string> splitEnvList(const char *name) {
    const char *raw = std::getenv(name);
    if (raw == nullptr) {
        return {};
    }

    std::vector<std::string> items;
    std::stringstream stream(raw);
    std::string item;
    while (std::getline(stream, item, ',')) {
        item = trim(item);
        if (!item.empty()) {
            items.push_back(item);
        }
    }
    return items;
}

void loadHelperBlacklist(AnalyzerContext &ctx) {
    // 过滤 LLVM/sanitizer/runtime 等工具链辅助函数，减少分析噪声。
    static const std::vector<std::string> builtinExact = {};
    static const std::vector<std::string> builtinPrefix = {
        "llvm.",
        "__asan_",
        "__ubsan_",
        "__kasan_",
        "__msan_",
        "__tsan_",
        "__sanitizer_",
        "__llvm_profile_",
        "__gcov_",
    };

    ctx.helperBlacklistExact.insert(builtinExact.begin(), builtinExact.end());
    ctx.helperBlacklistPrefix.insert(
        ctx.helperBlacklistPrefix.end(),
        builtinPrefix.begin(),
        builtinPrefix.end()
    );

    for (const std::string &entry : splitEnvList("LLVM_API_ANALYZER_HELPER_BLACKLIST")) {
        if (entry.size() > 1 && entry.back() == '*') {
            ctx.helperBlacklistPrefix.push_back(entry.substr(0, entry.size() - 1));
            continue;
        }
        ctx.helperBlacklistExact.insert(entry);
    }
}

bool isUnderRoot(const fs::path &root, const fs::path &path) {
    const std::string rootText = root.generic_string();
    const std::string pathText = path.generic_string();
    if (pathText == rootText) {
        return true;
    }
    if (rootText.empty()) {
        return false;
    }
    return pathText.rfind(rootText + "/", 0) == 0;
}

std::string makeRepoRelative(const fs::path &repoRoot, const std::string &rawPath) {
    if (rawPath.empty()) {
        return "";
    }

    fs::path candidate(rawPath);
    std::error_code ec;
    fs::path normalizedRepo = fs::weakly_canonical(repoRoot, ec);
    if (ec) {
        normalizedRepo = repoRoot.lexically_normal();
    }

    fs::path normalizedPath;
    if (candidate.is_absolute()) {
        normalizedPath = fs::weakly_canonical(candidate, ec);
        if (ec) {
            normalizedPath = candidate.lexically_normal();
        }
    } else {
        normalizedPath = (normalizedRepo / candidate).lexically_normal();
    }

    if (isUnderRoot(normalizedRepo, normalizedPath)) {
        return normalizedPath.lexically_relative(normalizedRepo).generic_string();
    }
    return normalizedPath.generic_string();
}

// 3. 符号归一化、位置恢复与调用目标解析
SourceLocation resolveLocation(const AnalyzerContext &ctx, const DILocation *location) {
    if (location == nullptr) {
        return {};
    }

    const std::string fileName = location->getFilename().str();
    const std::string directory = location->getDirectory().str();
    fs::path path = directory.empty() ? fs::path(fileName) : fs::path(directory) / fileName;
    return {makeRepoRelative(ctx.repoRoot, path.generic_string()), location->getLine()};
}

SourceLocation resolveFunctionLocation(const AnalyzerContext &ctx, const Function &function) {
    const DISubprogram *subprogram = function.getSubprogram();
    if (subprogram == nullptr) {
        return {};
    }

    const std::string fileName = subprogram->getFilename().str();
    const std::string directory = subprogram->getDirectory().str();
    fs::path path = directory.empty() ? fs::path(fileName) : fs::path(directory) / fileName;
    return {makeRepoRelative(ctx.repoRoot, path.generic_string()), subprogram->getLine()};
}

std::string moduleStableId(const AnalyzerContext &ctx, const Module &module) {
    const std::string sourceFile = module.getSourceFileName();
    if (!sourceFile.empty()) {
        const std::string repoRelative = makeRepoRelative(ctx.repoRoot, sourceFile);
        if (!repoRelative.empty()) {
            return repoRelative;
        }
    }

    const std::string moduleId = module.getModuleIdentifier();
    if (!moduleId.empty()) {
        const std::string repoRelative = makeRepoRelative(ctx.repoRoot, moduleId);
        if (!repoRelative.empty()) {
            return repoRelative;
        }
        return moduleId;
    }

    return "unknown_module";
}

std::string nodeSourceAnchor(
    const AnalyzerContext &ctx,
    const Function &function,
    const SourceLocation &location
) {
    if (!location.file.empty()) {
        return location.file;
    }

    SourceLocation functionLocation = resolveFunctionLocation(ctx, function);
    if (!functionLocation.file.empty()) {
        return functionLocation.file;
    }

    return moduleStableId(ctx, *function.getParent());
}

std::string nodeAddress(
    const AnalyzerContext &ctx,
    const Function &function,
    size_t instructionOrder,
    const SourceLocation &location
) {
    return nodeSourceAnchor(ctx, function, location) +
           "::" + function.getName().str() +
           ":" + std::to_string(instructionOrder);
}

bool shouldSkipIntrinsicCallee(const Function *callee) {
    if (callee == nullptr) {
        return true;
    }
    if (callee->isIntrinsic()) {
        return true;
    }
    const StringRef name = callee->getName();
    return name.contains("llvm.dbg.") || name.contains("llvm.lifetime.") || name.contains("llvm.assume") ||
           name.contains("llvm.frameaddress") || name.contains("llvm.fshl") ||
           name.contains("llvm.returnaddress");
}

bool isBlacklistedHelper(const AnalyzerContext &ctx, const Function &callee) {
    const std::string name = callee.getName().str();
    if (ctx.helperBlacklistExact.find(name) != ctx.helperBlacklistExact.end()) {
        return true;
    }
    for (const std::string &prefix : ctx.helperBlacklistPrefix) {
        if (!prefix.empty() && name.rfind(prefix, 0) == 0) {
            return true;
        }
    }
    return false;
}

std::string valueText(Value *value) {
    if (value == nullptr) {
        return "";
    }
    std::string text;
    raw_string_ostream stream(text);
    value->printAsOperand(stream, false);
    stream.flush();
    return trim(text);
}

void appendTags(std::set<int> &target, const std::set<int> &source) {
    target.insert(source.begin(), source.end());
}

std::set<int> mergedTagsForValue(const RelateMap &brvSet, const RelateMap &trackedSet, Value *value) {
    std::set<int> tags;
    auto brvIt = brvSet.find(value);
    if (brvIt != brvSet.end()) {
        appendTags(tags, brvIt->second);
    }
    auto trackedIt = trackedSet.find(value);
    if (trackedIt != trackedSet.end()) {
        appendTags(tags, trackedIt->second);
    }
    return tags;
}

bool addResolvedCallee(
    Function *callee,
    std::vector<Function *> &callees,
    std::unordered_set<const Function *> &seen,
    bool &candidateCapHit
) {
    if (callee == nullptr || shouldSkipIntrinsicCallee(callee)) {
        return false;
    }
    if (seen.find(callee) != seen.end()) {
        return false;
    }
    if (callees.size() >= 8) {
        candidateCapHit = true;
        return false;
    }
    seen.insert(callee);
    callees.push_back(callee);
    return true;
}

void collectResolvedCallees(
    Value *value,
    std::vector<Function *> &callees,
    std::unordered_set<const Function *> &seen,
    bool &candidateCapHit,
    unsigned depth = 0
) {
    if (value == nullptr || depth > 5 || candidateCapHit) {
        return;
    }

    value = value->stripPointerCasts();
    if (auto *callee = dyn_cast<Function>(value)) {
        addResolvedCallee(callee, callees, seen, candidateCapHit);
        return;
    }
    if (auto *alias = dyn_cast<GlobalAlias>(value)) {
        if (Constant *aliasee = alias->getAliasee()) {
            collectResolvedCallees(aliasee, callees, seen, candidateCapHit, depth + 1);
        }
        return;
    }
    if (auto *constantExpr = dyn_cast<ConstantExpr>(value)) {
        for (Use &operand : constantExpr->operands()) {
            collectResolvedCallees(operand.get(), callees, seen, candidateCapHit, depth + 1);
            if (candidateCapHit) {
                return;
            }
        }
        return;
    }
    if (auto *selectInst = dyn_cast<SelectInst>(value)) {
        collectResolvedCallees(selectInst->getTrueValue(), callees, seen, candidateCapHit, depth + 1);
        collectResolvedCallees(selectInst->getFalseValue(), callees, seen, candidateCapHit, depth + 1);
        return;
    }
    if (auto *phiNode = dyn_cast<PHINode>(value)) {
        for (unsigned index = 0; index < phiNode->getNumIncomingValues(); ++index) {
            collectResolvedCallees(phiNode->getIncomingValue(index), callees, seen, candidateCapHit, depth + 1);
            if (candidateCapHit) {
                return;
            }
        }
        return;
    }
    if (auto *loadInst = dyn_cast<LoadInst>(value)) {
        collectResolvedCallees(loadInst->getPointerOperand(), callees, seen, candidateCapHit, depth + 1);
        return;
    }
    if (auto *getElementPtr = dyn_cast<GetElementPtrInst>(value)) {
        collectResolvedCallees(getElementPtr->getPointerOperand(), callees, seen, candidateCapHit, depth + 1);
        return;
    }
    if (auto *global = dyn_cast<GlobalVariable>(value)) {
        if (global->hasInitializer()) {
            collectResolvedCallees(global->getInitializer(), callees, seen, candidateCapHit, depth + 1);
        }
        return;
    }
    if (auto *constantStruct = dyn_cast<ConstantStruct>(value)) {
        for (Use &operand : constantStruct->operands()) {
            collectResolvedCallees(operand.get(), callees, seen, candidateCapHit, depth + 1);
            if (candidateCapHit) {
                return;
            }
        }
        return;
    }
    if (auto *constantArray = dyn_cast<ConstantArray>(value)) {
        for (Use &operand : constantArray->operands()) {
            collectResolvedCallees(operand.get(), callees, seen, candidateCapHit, depth + 1);
            if (candidateCapHit) {
                return;
            }
        }
        return;
    }
    if (auto *constantVector = dyn_cast<ConstantVector>(value)) {
        for (Use &operand : constantVector->operands()) {
            collectResolvedCallees(operand.get(), callees, seen, candidateCapHit, depth + 1);
            if (candidateCapHit) {
                return;
            }
        }
    }
}

ResolvedCallTargets resolvePotentialCallees(const CallBase &call) {
    // 对间接调用做有限深度的静态恢复，尽量把候选 callee 找出来。
    ResolvedCallTargets targets;
    if (Function *callee = call.getCalledFunction()) {
        if (!shouldSkipIntrinsicCallee(callee)) {
            targets.callees.push_back(callee);
        }
        return targets;
    }

    targets.isIndirect = true;
    std::unordered_set<const Function *> seen;
    collectResolvedCallees(call.getCalledOperand(), targets.callees, seen, targets.candidateCapHit);
    targets.unresolved = targets.callees.empty();
    return targets;
}

std::string displayCallName(const CallBase &call, const ResolvedCallTargets &targets) {
    if (!targets.isIndirect && targets.callees.empty()) {
        return "";
    }
    if (!targets.callees.empty() && !targets.isIndirect) {
        return targets.callees.front()->getName().str();
    }
    if (targets.callees.size() == 1) {
        return targets.callees.front()->getName().str();
    }
    return "INDIRECT_CALL";
}

std::string classifySinkName(const AnalyzerContext &ctx, const std::string &name) {
    const std::string loweredName = toLowerCopy(name);
    for (const SinkRuleSet &rule : ctx.sinkRules) {
        if (rule.exact.find(loweredName) != rule.exact.end()) {
            return rule.kind;
        }
        for (const std::string &prefix : rule.prefix) {
            if (loweredName.rfind(prefix, 0) == 0) {
                return rule.kind;
            }
        }
        for (const std::string &token : rule.contains) {
            if (loweredName.find(token) != std::string::npos) {
                return rule.kind;
            }
        }
    }
    return "";
}

std::vector<int> sortedParams(const std::set<int> &params) {
    return std::vector<int>(params.begin(), params.end());
}

int positiveParamCount(const std::set<int> &params) {
    int count = 0;
    for (int parameter : params) {
        if (parameter > 0) {
            ++count;
        }
    }
    return count;
}

bool isConstantValue(Value *value) {
    return value != nullptr && isa<Constant>(value);
}

bool ensureDirectory(const fs::path &path) {
    std::error_code ec;
    fs::create_directories(path, ec);
    return !ec;
}

// 4. 超时控制与图节点构建
void appendTimeoutLog(const AnalyzerContext &ctx, RootAnalysisState &state) {
    // instruction/function/file 三层超时共享一份日志，便于回放失败 root。
    if (state.timedOut) {
        return;
    }

    const double instructionDuration = static_cast<double>(std::clock() - state.instructionStartTime) / CLOCKS_PER_SEC;
    const double functionDuration = static_cast<double>(std::clock() - state.functionStartTime) / CLOCKS_PER_SEC;
    const double fileDuration = static_cast<double>(std::clock() - state.fileStartTime) / CLOCKS_PER_SEC;

    ensureDirectory(ctx.timeoutLog.parent_path());
    std::ofstream handle(ctx.timeoutLog, std::ios::app);
    handle << "Timeout: {project: " << ctx.projectId
           << ", file: " << state.fileName
           << ", function: " << state.functionName
           << ", api: " << state.apiName
           << ", instructionDuration: " << instructionDuration
           << " seconds, functionDuration: " << functionDuration
           << " seconds, fileDuration: " << fileDuration
           << " seconds}\n";
    state.timedOut = true;
}

bool isTimedOut(const AnalyzerContext &ctx, RootAnalysisState &state) {
    if (state.timedOut) {
        return true;
    }

    const double instructionDuration = static_cast<double>(std::clock() - state.instructionStartTime) / CLOCKS_PER_SEC;
    const double functionDuration = static_cast<double>(std::clock() - state.functionStartTime) / CLOCKS_PER_SEC;
    const double fileDuration = static_cast<double>(std::clock() - state.fileStartTime) / CLOCKS_PER_SEC;
    if (instructionDuration > 60.0 || functionDuration > 3600.0 || fileDuration > 36000.0) {
        appendTimeoutLog(ctx, state);
        return true;
    }
    return false;
}

void linkNodes(APIPath *from, APIPath *to) {
    if (from == nullptr || to == nullptr || from == to) {
        return;
    }
    from->next.insert(to);
    to->prev.insert(from);
}

APIPath *makeEmptyPath() {
    return new APIPath();
}

APIPath *makeOperationPath(
    const AnalyzerContext &ctx,
    Function &function,
    Instruction &instruction,
    const std::string &name,
    const std::set<int> &params,
    const OrderMap &orderByInst,
    RootAnalysisState &state
) {
    // 为一个 call/check 指令创建可序列化的图节点。
    auto orderIt = orderByInst.find(&instruction);
    if (orderIt == orderByInst.end()) {
        return nullptr;
    }

    SourceLocation location;
    if (const DILocation *debugLoc = instruction.getDebugLoc().get()) {
        location = resolveLocation(ctx, debugLoc);
    }
    if (location.file.empty()) {
        location = resolveFunctionLocation(ctx, function);
    }

    APIPath *node = new APIPath();
    node->name = name;
    node->address = nodeAddress(ctx, function, orderIt->second, location);
    node->parameter = params;
    node->file = location.file;
    node->line = location.line;
    node->sinkKind = classifySinkName(ctx, name);
    node->order = orderIt->second;
    node->serial = state.nextSerial++;
    state.nodeCount += 1;
    return node;
}

void cleanupPlaceholderTracking(RelateMap &rvSet, RelateMap &trackedSet) {
    std::set<Value *> unresolved;
    for (const auto &tracked : trackedSet) {
        if (tracked.second.find(-1) != tracked.second.end()) {
            unresolved.insert(tracked.first);
        }
    }

    for (Value *value : unresolved) {
        trackedSet[value].erase(-1);
        if (trackedSet[value].empty()) {
            trackedSet.erase(value);
        }
        auto rvIt = rvSet.find(value);
        if (rvIt != rvSet.end()) {
            rvIt->second.erase(-1);
            if (rvIt->second.empty()) {
                rvSet.erase(rvIt);
            }
        }
    }
}

// 5. 相关变量传播：FRV/BRV
void findForwardRelateVariable(
    Value *value,
    RelateMap &frvSet,
    RelateMap &trackedSet,
    int parameter,
    const AnalyzerContext &ctx,
    RootAnalysisState &state,
    bool constantPointer = false
) {
    // 正向传播“与 root 参数相关”的值集合。
    if (isTimedOut(ctx, state) || value == nullptr) {
        return;
    }

    if (parameter == -1) {
        auto frvIt = frvSet.find(value);
        if (frvIt != frvSet.end()) {
            const std::set<int> parameterValues = frvIt->second;
            std::set<Value *> relateVariables;
            for (const auto &tracked : trackedSet) {
                if (tracked.second.find(-1) != tracked.second.end()) {
                    relateVariables.insert(tracked.first);
                }
            }
            for (Value *relate : relateVariables) {
                trackedSet[relate].erase(-1);
                trackedSet[relate].insert(parameterValues.begin(), parameterValues.end());
                auto relateIt = frvSet.find(relate);
                if (relateIt != frvSet.end()) {
                    relateIt->second.erase(-1);
                    relateIt->second.insert(parameterValues.begin(), parameterValues.end());
                }
            }
            return;
        }
    } else {
        auto trackedIt = trackedSet.find(value);
        if (trackedIt != trackedSet.end() && trackedIt->second.find(parameter) != trackedIt->second.end()) {
            return;
        }
    }

    trackedSet[value].insert(parameter);
    if (isConstantValue(value)) {
        if (constantPointer) {
            frvSet[value].insert(parameter);
        }
        return;
    }

    if (isa<Argument>(value) || isa<GlobalVariable>(value) || isa<AllocaInst>(value)) {
        frvSet[value].insert(parameter);
        return;
    }

    if (auto *constantExpr = dyn_cast<ConstantExpr>(value)) {
        if (constantExpr->getNumOperands() > 0) {
            findForwardRelateVariable(
                constantExpr->getOperand(0),
                frvSet,
                trackedSet,
                parameter,
                ctx,
                state
            );
        }
        return;
    }

    if (auto *callInst = dyn_cast<CallBase>(value)) {
        frvSet[value].insert(parameter);
        for (Use &arg : callInst->args()) {
            findForwardRelateVariable(arg.get(), frvSet, trackedSet, parameter, ctx, state);
        }
        return;
    }

    if (auto *selectInst = dyn_cast<SelectInst>(value)) {
        frvSet[value].insert(parameter);
        findForwardRelateVariable(selectInst->getTrueValue(), frvSet, trackedSet, parameter, ctx, state);
        findForwardRelateVariable(selectInst->getFalseValue(), frvSet, trackedSet, parameter, ctx, state);
        return;
    }

    if (auto *getElementPtr = dyn_cast<GetElementPtrInst>(value)) {
        frvSet[value].insert(parameter);
        findForwardRelateVariable(getElementPtr->getPointerOperand(), frvSet, trackedSet, parameter, ctx, state);
        return;
    }

    if (auto *phiNode = dyn_cast<PHINode>(value)) {
        frvSet[value].insert(parameter);
        for (unsigned index = 0; index < phiNode->getNumIncomingValues(); ++index) {
            findForwardRelateVariable(
                phiNode->getIncomingValue(index),
                frvSet,
                trackedSet,
                parameter,
                ctx,
                state
            );
        }
        return;
    }

    if (auto *icmpInst = dyn_cast<ICmpInst>(value)) {
        frvSet[value].insert(parameter);
        for (unsigned index = 0; index < icmpInst->getNumOperands(); ++index) {
            findForwardRelateVariable(icmpInst->getOperand(index), frvSet, trackedSet, parameter, ctx, state);
        }
        return;
    }

    if (auto *loadInst = dyn_cast<LoadInst>(value)) {
        frvSet[value].insert(parameter);
        findForwardRelateVariable(loadInst->getPointerOperand(), frvSet, trackedSet, parameter, ctx, state);
        return;
    }

    if (auto *unaryInst = dyn_cast<UnaryInstruction>(value)) {
        frvSet[value].insert(parameter);
        findForwardRelateVariable(unaryInst->getOperand(0), frvSet, trackedSet, parameter, ctx, state);
        return;
    }

    if (auto *binaryOp = dyn_cast<BinaryOperator>(value)) {
        frvSet[value].insert(parameter);
        for (unsigned index = 0; index < binaryOp->getNumOperands(); ++index) {
            findForwardRelateVariable(binaryOp->getOperand(index), frvSet, trackedSet, parameter, ctx, state);
        }
        return;
    }

    if (auto *storeInst = dyn_cast<StoreInst>(value)) {
        frvSet[value].insert(parameter);
        findForwardRelateVariable(storeInst->getValueOperand(), frvSet, trackedSet, parameter, ctx, state);
        findForwardRelateVariable(storeInst->getPointerOperand(), frvSet, trackedSet, parameter, ctx, state, true);
        return;
    }
}

void findBackwardRelateVariable(
    RelateMap &frvSet,
    RelateMap &brvSet,
    const AnalyzerContext &ctx,
    RootAnalysisState &state
) {
    // 基于 FRV 结果回填 BRV，得到后续操作筛选需要的相关值。
    if (isTimedOut(ctx, state)) {
        return;
    }

    for (const auto &frv : frvSet) {
        brvSet[frv.first].insert(frv.second.begin(), frv.second.end());
        for (User *user : frv.first->users()) {
            if (isConstantValue(user)) {
                continue;
            }
            for (int parameter : frv.second) {
                if (auto *storeInst = dyn_cast<StoreInst>(user)) {
                    if (storeInst->getValueOperand() == frv.first) {
                        brvSet[storeInst->getPointerOperand()].insert(parameter);
                    }
                }
                brvSet[user].insert(parameter);
            }
        }
    }

    bool changed = false;
    for (const auto &brv : brvSet) {
        for (int parameter : brv.second) {
            if (frvSet[brv.first].insert(parameter).second) {
                changed = true;
            }
        }
    }
    if (!changed) {
        return;
    }

    findBackwardRelateVariable(frvSet, brvSet, ctx, state);
}

bool isRelateOperation(
    Value *value,
    RelateMap &rvSet,
    RelateMap &trackedSet,
    const AnalyzerContext &ctx,
    RootAnalysisState &state
) {
    if (isTimedOut(ctx, state) || value == nullptr) {
        return false;
    }
    if (rvSet.find(value) != rvSet.end()) {
        return true;
    }

    findForwardRelateVariable(value, rvSet, trackedSet, -1, ctx, state);
    cleanupPlaceholderTracking(rvSet, trackedSet);
    return rvSet.find(value) != rvSet.end();
}

Value *controlOperand(Instruction *instruction) {
    if (auto *branchInst = dyn_cast<BranchInst>(instruction)) {
        if (branchInst->getNumSuccessors() < 2) {
            return nullptr;
        }
        return branchInst->getCondition();
    }
    if (auto *switchInst = dyn_cast<SwitchInst>(instruction)) {
        if (switchInst->getNumSuccessors() < 2) {
            return nullptr;
        }
        return switchInst->getCondition();
    }
    if (auto *selectInst = dyn_cast<SelectInst>(instruction)) {
        return selectInst->getCondition();
    }
    if (auto *returnInst = dyn_cast<ReturnInst>(instruction)) {
        return returnInst->getReturnValue();
    }
    return nullptr;
}

std::set<int> relatedTagsForValue(const RelateMap &brvSet, Value *value) {
    auto it = brvSet.find(value);
    if (it == brvSet.end()) {
        return {};
    }
    return it->second;
}

std::string checkKindForInstruction(Instruction &instruction) {
    if (isa<BranchInst>(instruction)) {
        return "branch";
    }
    if (isa<SwitchInst>(instruction)) {
        return "switch";
    }
    if (isa<SelectInst>(instruction)) {
        return "select";
    }
    if (isa<ReturnInst>(instruction)) {
        return "return_guard";
    }
    return "";
}

unsigned branchCountForInstruction(Instruction &instruction) {
    if (auto *branchInst = dyn_cast<BranchInst>(&instruction)) {
        return branchInst->getNumSuccessors();
    }
    if (auto *switchInst = dyn_cast<SwitchInst>(&instruction)) {
        return switchInst->getNumSuccessors();
    }
    if (isa<SelectInst>(instruction)) {
        return 2;
    }
    return 0;
}

// 6. 跨函数摘要与同模块展开
Value *pointerBase(Value *value, unsigned depth = 0) {
    if (value == nullptr || depth > 6) {
        return nullptr;
    }
    value = value->stripPointerCasts();
    if (isa<Argument>(value) || isa<GlobalVariable>(value) || isa<AllocaInst>(value)) {
        return value;
    }
    if (auto *getElementPtr = dyn_cast<GetElementPtrInst>(value)) {
        return pointerBase(getElementPtr->getPointerOperand(), depth + 1);
    }
    if (auto *constantExpr = dyn_cast<ConstantExpr>(value)) {
        if (constantExpr->getOpcode() == Instruction::GetElementPtr && constantExpr->getNumOperands() > 0) {
            return pointerBase(constantExpr->getOperand(0), depth + 1);
        }
        if (constantExpr->isCast() && constantExpr->getNumOperands() > 0) {
            return pointerBase(constantExpr->getOperand(0), depth + 1);
        }
    }
    return nullptr;
}

void collectCalleeSummary(
    Function &callee,
    const RelateMap &calleeBrvSet,
    const RelateMap &calleeTrackedSet,
    CalleeSummary &summary
) {
    // 抽取 callee 的 return / pointer-write / global-write 标签摘要。
    for (BasicBlock &block : callee) {
        for (Instruction &instruction : block) {
            if (auto *returnInst = dyn_cast<ReturnInst>(&instruction)) {
                appendTags(summary.returnTags, mergedTagsForValue(calleeBrvSet, calleeTrackedSet, returnInst->getReturnValue()));
                continue;
            }
            auto *storeInst = dyn_cast<StoreInst>(&instruction);
            if (storeInst == nullptr) {
                continue;
            }
            std::set<int> tags = mergedTagsForValue(calleeBrvSet, calleeTrackedSet, storeInst->getValueOperand());
            appendTags(tags, mergedTagsForValue(calleeBrvSet, calleeTrackedSet, &instruction));
            if (tags.empty()) {
                continue;
            }
            Value *base = pointerBase(storeInst->getPointerOperand());
            if (base == nullptr) {
                continue;
            }
            if (auto *formal = dyn_cast<Argument>(base)) {
                if (formal->getType()->isPointerTy()) {
                    appendTags(summary.pointerArgumentTags[formal->getArgNo()], tags);
                }
                continue;
            }
            if (isa<GlobalVariable>(base)) {
                appendTags(summary.globalTags[base], tags);
            }
        }
    }
}

void mergeTagsIntoValue(RelateMap &brvSet, RelateMap &trackedSet, Value *value, const std::set<int> &tags) {
    if (value == nullptr || tags.empty()) {
        return;
    }
    appendTags(brvSet[value], tags);
    appendTags(trackedSet[value], tags);
}

void applyCalleeSummaryToCaller(
    CallBase &callInst,
    const CalleeSummary &summary,
    RelateMap &callerBrvSet,
    RelateMap &callerTrackedSet
) {
    mergeTagsIntoValue(callerBrvSet, callerTrackedSet, &callInst, summary.returnTags);
    for (const auto &entry : summary.pointerArgumentTags) {
        if (entry.first >= callInst.arg_size()) {
            continue;
        }
        Value *actual = callInst.getArgOperand(entry.first);
        mergeTagsIntoValue(callerBrvSet, callerTrackedSet, actual, entry.second);
        Value *base = pointerBase(actual);
        if (base != nullptr && base != actual) {
            mergeTagsIntoValue(callerBrvSet, callerTrackedSet, base, entry.second);
        }
    }
    for (const auto &entry : summary.globalTags) {
        mergeTagsIntoValue(callerBrvSet, callerTrackedSet, entry.first, entry.second);
    }
}

bool canExpandIntoCallee(
    const AnalyzerContext &ctx,
    RootAnalysisState &state,
    Function &caller,
    const Function *callee
) {
    if (callee == nullptr) {
        return false;
    }
    if (callee->empty() || callee->isDeclaration() || shouldSkipIntrinsicCallee(callee)) {
        return false;
    }
    if (callee->getParent() != caller.getParent()) {
        return false;
    }
    if (isBlacklistedHelper(ctx, *callee)) {
        return false;
    }
    if (!state.expansionStack.empty() && state.expansionStack.size() - 1 >= ctx.maxCrossFunctionDepth) {
        state.crossFunctionBudgetHit = true;
        state.warnings.insert("cross_function_budget_hit");
        return false;
    }
    return std::find(state.expansionStack.begin(), state.expansionStack.end(), callee) == state.expansionStack.end();
}

bool seedCalleeRelateMaps(
    CallBase &callInst,
    Function &callee,
    RelateMap &calleeFrvSet,
    RelateMap &calleeBrvSet,
    RelateMap &calleeTrackedSet,
    const RelateMap &callerBrvSet,
    const RelateMap &callerTrackedSet,
    const AnalyzerContext &ctx,
    RootAnalysisState &state
) {
    bool seeded = false;
    const std::set<int> callTags = relatedTagsForValue(callerBrvSet, &callInst);
    auto formalIt = callee.arg_begin();
    for (unsigned index = 0; index < callInst.arg_size() && formalIt != callee.arg_end(); ++index, ++formalIt) {
        Value *actual = callInst.getArgOperand(index);
        std::set<int> tags = relatedTagsForValue(callerBrvSet, actual);
        if (tags.empty()) {
            tags = relatedTagsForValue(callerTrackedSet, actual);
        }
        if (tags.empty()) {
            tags = callTags;
        }
        if (tags.empty()) {
            continue;
        }

        Argument *formal = &*formalIt;
        for (int tag : tags) {
            findForwardRelateVariable(formal, calleeFrvSet, calleeTrackedSet, tag, ctx, state);
        }
        seeded = true;
    }

    if (!seeded) {
        return false;
    }

    findBackwardRelateVariable(calleeFrvSet, calleeBrvSet, ctx, state);
    return !calleeBrvSet.empty();
}

void findRelateOperation(
    BasicBlock *block,
    RelateMap &brvSet,
    Instruction *injectedInstruction,
    APIPath *injectedNode,
    APIPath *prevEnd,
    VisitMap &visitBlocks,
    std::set<APIPath *> &apiList,
    RelateMap &trackedSet,
    const AnalyzerContext &ctx,
    Function &function,
    const FunctionOrderMap &orderByFunction,
    APIPath *terminalJoin,
    RootAnalysisState &state
);

bool analyzeCallee(
    CallBase &callInst,
    RelateMap &callerBrvSet,
    RelateMap &callerTrackedSet,
    std::set<APIPath *> &apiList,
    const AnalyzerContext &ctx,
    Function &caller,
    const FunctionOrderMap &orderByFunction,
    Function &callee,
    APIPath *callNode,
    APIPath *returnJoin,
    bool traverseOperations,
    RootAnalysisState &state
) {
    // 先做 callee 摘要回传，再按需继续展开 callee 内部相关操作。
    if (!canExpandIntoCallee(ctx, state, caller, &callee)) {
        return false;
    }

    auto orderIt = orderByFunction.find(&callee);
    if (orderIt == orderByFunction.end()) {
        return false;
    }

    RelateMap calleeFrvSet;
    RelateMap calleeBrvSet;
    RelateMap calleeTrackedSet;
    if (!seedCalleeRelateMaps(
            callInst,
            callee,
            calleeFrvSet,
            calleeBrvSet,
            calleeTrackedSet,
            callerBrvSet,
            callerTrackedSet,
            ctx,
            state
        )) {
        return false;
    }

    CalleeSummary summary;
    collectCalleeSummary(callee, calleeBrvSet, calleeTrackedSet, summary);
    applyCalleeSummaryToCaller(callInst, summary, callerBrvSet, callerTrackedSet);

    if (!traverseOperations) {
        return !summary.returnTags.empty() || !summary.pointerArgumentTags.empty() || !summary.globalTags.empty();
    }

    VisitMap calleeVisits;
    state.expansionStack.push_back(&callee);
    findRelateOperation(
        &callee.getEntryBlock(),
        calleeBrvSet,
        nullptr,
        nullptr,
        callNode,
        calleeVisits,
        apiList,
        calleeTrackedSet,
        ctx,
        callee,
        orderByFunction,
        returnJoin,
        state
    );
    state.expansionStack.pop_back();
    return true;
}

bool expandIntoResolvedCallees(
    CallBase &callInst,
    const ResolvedCallTargets &targets,
    APIPath *callNode,
    APIPath *returnJoin,
    RelateMap &callerBrvSet,
    RelateMap &callerTrackedSet,
    std::set<APIPath *> &apiList,
    const AnalyzerContext &ctx,
    Function &caller,
    const FunctionOrderMap &orderByFunction,
    RootAnalysisState &state
) {
    bool expanded = false;
    for (Function *callee : targets.callees) {
        if (callee == nullptr) {
            continue;
        }
        expanded = analyzeCallee(
            callInst,
            callerBrvSet,
            callerTrackedSet,
            apiList,
            ctx,
            caller,
            orderByFunction,
            *callee,
            callNode,
            returnJoin,
            true,
            state
        ) || expanded;
    }
    return expanded;
}

bool summarizeResolvedCalleesIntoCaller(
    CallBase &callInst,
    const ResolvedCallTargets &targets,
    RelateMap &callerBrvSet,
    RelateMap &callerTrackedSet,
    std::set<APIPath *> &apiList,
    const AnalyzerContext &ctx,
    Function &caller,
    const FunctionOrderMap &orderByFunction,
    RootAnalysisState &state
) {
    bool changed = false;
    for (Function *callee : targets.callees) {
        if (callee == nullptr) {
            continue;
        }
        changed = analyzeCallee(
            callInst,
            callerBrvSet,
            callerTrackedSet,
            apiList,
            ctx,
            caller,
            orderByFunction,
            *callee,
            nullptr,
            nullptr,
            false,
            state
        ) || changed;
    }
    return changed;
}

// 7. CFG 遍历与路径图恢复
void findRelateOperation(
    BasicBlock *block,
    RelateMap &brvSet,
    Instruction *injectedInstruction,
    APIPath *injectedNode,
    APIPath *prevEnd,
    VisitMap &visitBlocks,
    std::set<APIPath *> &apiList,
    RelateMap &trackedSet,
    const AnalyzerContext &ctx,
    Function &function,
    const FunctionOrderMap &orderByFunction,
    APIPath *terminalJoin,
    RootAnalysisState &state
) {
    // 在 CFG 上递归恢复与 root 相关的 call/check 子图。
    if (isTimedOut(ctx, state) || block == nullptr) {
        return;
    }

    auto visitIt = visitBlocks.find(block);
    if (visitIt != visitBlocks.end()) {
        if (prevEnd != nullptr) {
            linkNodes(prevEnd, visitIt->second.first);
        }
        return;
    }

    APIPath *begin = makeEmptyPath();
    APIPath *end = makeEmptyPath();
    APIPath *current = begin;
    apiList.insert(begin);
    apiList.insert(end);

    auto orderIt = orderByFunction.find(&function);
    if (orderIt == orderByFunction.end()) {
        return;
    }
    const OrderMap &orderByInst = orderIt->second;
    for (Instruction &instruction : *block) {
        Value *value = &instruction;
        if (injectedInstruction != nullptr && value == injectedInstruction && injectedNode != nullptr) {
            linkNodes(current, injectedNode);
            current = injectedNode;
            if (auto *injectedCall = dyn_cast<CallBase>(value)) {
                const ResolvedCallTargets callTargets = resolvePotentialCallees(*injectedCall);
                APIPath *returnJoin = makeEmptyPath();
                apiList.insert(returnJoin);
                const bool expandedIntoCallee = expandIntoResolvedCallees(
                    *injectedCall,
                    callTargets,
                    injectedNode,
                    returnJoin,
                    brvSet,
                    trackedSet,
                    apiList,
                    ctx,
                    function,
                    orderByFunction,
                    state
                );
                if (expandedIntoCallee) {
                    current = returnJoin;
                } else {
                    apiList.erase(returnJoin);
                    delete returnJoin;
                }
            }
            continue;
        }

        if (auto *callInst = dyn_cast<CallBase>(value)) {
            const ResolvedCallTargets callTargets = resolvePotentialCallees(*callInst);
            if (callTargets.isIndirect) {
                if (callTargets.candidateCapHit) {
                    ++state.indirectCandidateCapHitSites;
                    state.warnings.insert("indirect_call_candidate_cap_hit");
                }
                if (callTargets.unresolved) {
                    ++state.unresolvedIndirectCallSites;
                    state.warnings.insert("indirect_call_unresolved");
                } else {
                    ++state.resolvedIndirectCallSites;
                }
            }

            bool related = isRelateOperation(value, brvSet, trackedSet, ctx, state);
            if (!related && !callTargets.callees.empty()) {
                bool hasTrackedInputs = !mergedTagsForValue(brvSet, trackedSet, callInst->getCalledOperand()).empty();
                for (Use &arg : callInst->args()) {
                    if (!mergedTagsForValue(brvSet, trackedSet, arg.get()).empty()) {
                        hasTrackedInputs = true;
                        break;
                    }
                }
                if (hasTrackedInputs) {
                    summarizeResolvedCalleesIntoCaller(
                        *callInst,
                        callTargets,
                        brvSet,
                        trackedSet,
                        apiList,
                        ctx,
                        function,
                        orderByFunction,
                        state
                    );
                    related = isRelateOperation(value, brvSet, trackedSet, ctx, state);
                }
            }

            if (!related) {
                continue;
            }

            if (!callTargets.isIndirect && callTargets.callees.empty()) {
                continue;
            }

            const std::string calleeName = displayCallName(*callInst, callTargets);
            if (calleeName.empty()) {
                continue;
            }

            APIPath *node = makeOperationPath(ctx, function, instruction, calleeName, brvSet[value], orderByInst, state);
            if (node == nullptr) {
                continue;
            }
            node->callKind = callTargets.isIndirect ? "indirect" : "direct";
            node->unresolvedIndirect = callTargets.isIndirect && callTargets.unresolved;
            for (Function *callee : callTargets.callees) {
                if (callee != nullptr) {
                    node->resolvedCallees.push_back(callee->getName().str());
                }
            }
            apiList.insert(node);
            linkNodes(current, node);
            current = node;

            APIPath *returnJoin = makeEmptyPath();
            apiList.insert(returnJoin);
            const bool expandedIntoCallee = expandIntoResolvedCallees(
                *callInst,
                callTargets,
                node,
                returnJoin,
                brvSet,
                trackedSet,
                apiList,
                ctx,
                function,
                orderByFunction,
                state
            );
            if (expandedIntoCallee) {
                current = returnJoin;
            } else {
                apiList.erase(returnJoin);
                delete returnJoin;
            }
            continue;
        }

        if (isa<BranchInst>(value) || isa<SwitchInst>(value) || isa<SelectInst>(value) || isa<ReturnInst>(value)) {
            Value *cond = controlOperand(&instruction);
            if (!isRelateOperation(cond, brvSet, trackedSet, ctx, state)) {
                continue;
            }

            APIPath *node = makeOperationPath(ctx, function, instruction, "CHECK", brvSet[cond], orderByInst, state);
            if (node == nullptr) {
                continue;
            }
            node->checkKind = checkKindForInstruction(instruction);
            node->conditionText = valueText(cond);
            node->branchCount = branchCountForInstruction(instruction);
            apiList.insert(node);
            linkNodes(current, node);
            current = node;
        }
    }

    linkNodes(current, end);
    if (prevEnd != nullptr) {
        linkNodes(prevEnd, begin);
    }

    visitBlocks[block] = std::make_pair(begin, end);
    if (terminalJoin != nullptr && succ_empty(block)) {
        linkNodes(end, terminalJoin);
    }
    for (BasicBlock *successor : successors(block)) {
        findRelateOperation(
            successor,
            brvSet,
            injectedInstruction,
            injectedNode,
            end,
            visitBlocks,
            apiList,
            trackedSet,
            ctx,
            function,
            orderByFunction,
            terminalJoin,
            state
        );
    }
}

void collectConcreteNeighbors(
    APIPath *node,
    bool forward,
    std::set<APIPath *> &results,
    std::set<APIPath *> &seen
) {
    if (node == nullptr || seen.find(node) != seen.end()) {
        return;
    }
    seen.insert(node);

    const std::set<APIPath *> &neighbors = forward ? node->next : node->prev;
    for (APIPath *neighbor : neighbors) {
        if (neighbor == nullptr) {
            continue;
        }
        if (!neighbor->name.empty()) {
            results.insert(neighbor);
            continue;
        }
        collectConcreteNeighbors(neighbor, forward, results, seen);
    }
}

void clearEmptyAPIPath(std::set<APIPath *> &apiList) {
    for (APIPath *node : apiList) {
        if (node == nullptr || !node->name.empty()) {
            continue;
        }

        std::set<APIPath *> realPrevs;
        std::set<APIPath *> realNexts;
        std::set<APIPath *> seenPrev;
        std::set<APIPath *> seenNext;
        collectConcreteNeighbors(node, false, realPrevs, seenPrev);
        collectConcreteNeighbors(node, true, realNexts, seenNext);

        for (APIPath *prev : realPrevs) {
            for (APIPath *next : realNexts) {
                linkNodes(prev, next);
            }
        }
    }

    for (APIPath *node : apiList) {
        if (node == nullptr) {
            continue;
        }

        for (auto it = node->prev.begin(); it != node->prev.end();) {
            if (*it != nullptr && (*it)->name.empty()) {
                it = node->prev.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = node->next.begin(); it != node->next.end();) {
            if (*it != nullptr && (*it)->name.empty()) {
                it = node->next.erase(it);
            } else {
                ++it;
            }
        }
    }
}

std::vector<APIPath *> orderedNonEmptyNodes(const std::set<APIPath *> &apiList) {
    std::vector<APIPath *> nodes;
    nodes.reserve(apiList.size());
    for (APIPath *node : apiList) {
        if (node != nullptr && !node->name.empty()) {
            nodes.push_back(node);
        }
    }
    std::sort(
        nodes.begin(),
        nodes.end(),
        [](const APIPath *left, const APIPath *right) {
            if (left->serial != right->serial) {
                return left->serial < right->serial;
            }
            if (left->order != right->order) {
                return left->order < right->order;
            }
            return left->address < right->address;
        }
    );
    return nodes;
}

// 8. JSON 序列化与模块级分析
std::string vectorToJson(const std::vector<int> &items) {
    std::string json = "[";
    bool first = true;
    for (int item : items) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += std::to_string(item);
    }
    json += "]";
    return json;
}

std::string stringVectorToJson(const std::vector<std::string> &items) {
    std::string json = "[";
    bool first = true;
    for (const std::string &item : items) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += "\"" + jsonEscape(item) + "\"";
    }
    json += "]";
    return json;
}

std::string nextNodeToJson(const APIPath &node) {
    std::string json = "{";
    json += "\"AP\":\"" + jsonEscape(node.name) + "\",";
    json += "\"address\":\"" + jsonEscape(node.address) + "\",";
    json += "\"parameter\":" + vectorToJson(sortedParams(node.parameter)) + ",";
    json += "\"file\":\"" + jsonEscape(node.file) + "\",";
    json += "\"line\":" + std::to_string(node.line);
    if (!node.sinkKind.empty()) {
        json += ",\"sink_kind\":\"" + jsonEscape(node.sinkKind) + "\"";
    }
    if (!node.callKind.empty()) {
        json += ",\"call_kind\":\"" + jsonEscape(node.callKind) + "\"";
    }
    if (node.unresolvedIndirect) {
        json += ",\"unresolved_indirect\":true";
    }
    if (!node.resolvedCallees.empty()) {
        json += ",\"resolved_callees\":" + stringVectorToJson(node.resolvedCallees);
    }
    if (!node.checkKind.empty()) {
        json += ",\"check_kind\":\"" + jsonEscape(node.checkKind) + "\"";
    }
    if (!node.conditionText.empty()) {
        json += ",\"condition_text\":\"" + jsonEscape(node.conditionText) + "\"";
    }
    if (node.branchCount > 0) {
        json += ",\"branch_count\":" + std::to_string(node.branchCount);
    }
    json += "}";
    return json;
}

std::string nodeToJson(APIPath &node) {
    std::string json = "{";
    json += "\"AP\":\"" + jsonEscape(node.name) + "\",";
    json += "\"address\":\"" + jsonEscape(node.address) + "\",";
    json += "\"parameter\":" + vectorToJson(sortedParams(node.parameter)) + ",";
    json += "\"file\":\"" + jsonEscape(node.file) + "\",";
    json += "\"line\":" + std::to_string(node.line) + ",";
    if (!node.sinkKind.empty()) {
        json += "\"sink_kind\":\"" + jsonEscape(node.sinkKind) + "\",";
    }
    if (!node.callKind.empty()) {
        json += "\"call_kind\":\"" + jsonEscape(node.callKind) + "\",";
    }
    if (node.unresolvedIndirect) {
        json += "\"unresolved_indirect\":true,";
    }
    if (!node.resolvedCallees.empty()) {
        json += "\"resolved_callees\":" + stringVectorToJson(node.resolvedCallees) + ",";
    }
    if (!node.checkKind.empty()) {
        json += "\"check_kind\":\"" + jsonEscape(node.checkKind) + "\",";
    }
    if (!node.conditionText.empty()) {
        json += "\"condition_text\":\"" + jsonEscape(node.conditionText) + "\",";
    }
    if (node.branchCount > 0) {
        json += "\"branch_count\":" + std::to_string(node.branchCount) + ",";
    }
    json += "\"direct_next\":[";

    std::vector<APIPath *> orderedDirectDescendants;
    orderedDirectDescendants.reserve(node.next.size());
    for (APIPath *descendant : node.next) {
        if (descendant != nullptr && descendant != &node && !descendant->name.empty()) {
            orderedDirectDescendants.push_back(descendant);
        }
    }
    std::sort(
        orderedDirectDescendants.begin(),
        orderedDirectDescendants.end(),
        [](const APIPath *left, const APIPath *right) {
            if (left->serial != right->serial) {
                return left->serial < right->serial;
            }
            if (left->order != right->order) {
                return left->order < right->order;
            }
            return left->address < right->address;
        }
    );

    bool first = true;
    for (APIPath *descendant : orderedDirectDescendants) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += nextNodeToJson(*descendant);
    }
    json += "]}";
    return json;
}

void releaseAPIPath(std::set<APIPath *> &apiList, APIPath *root) {
    for (APIPath *node : apiList) {
        if (node != nullptr && node != root) {
            delete node;
        }
    }
}

std::string recordToJson(
    const std::string &file,
    const std::string &functionName,
    unsigned functionLine,
    APIPath &rootNode,
    const std::vector<APIPath *> &orderedNodes,
    RootAnalysisState &state
) {
    // 将单个 root call 的分析结果序列化为一条 DFA JSON 记录。
    std::string json = "{";
    json += "\"file\":\"" + jsonEscape(file) + "\",";
    json += "\"function\":\"" + jsonEscape(functionName) + "\",";
    json += "\"function_line\":" + std::to_string(functionLine) + ",";
    json += "\"API\":\"" + jsonEscape(rootNode.name) + "\",";
    json += "\"parameter\":" + vectorToJson(sortedParams(rootNode.parameter)) + ",";
    json += "\"address\":\"" + jsonEscape(rootNode.address) + "\",";
    if (!rootNode.sinkKind.empty()) {
        json += "\"sink_kind\":\"" + jsonEscape(rootNode.sinkKind) + "\",";
    }
    std::vector<std::string> warnings(state.warnings.begin(), state.warnings.end());
    json += "\"analysis_warnings\":" + stringVectorToJson(warnings) + ",";
    json += "\"analysis_stats\":{";
    json += "\"node_count\":" + std::to_string(state.nodeCount) + ",";
    json += "\"cross_function_budget_hit\":" + std::string(state.crossFunctionBudgetHit ? "true" : "false");
    json += "},";
    json += "\"indirect_call_stats\":{";
    json += "\"resolved_call_sites\":" + std::to_string(state.resolvedIndirectCallSites) + ",";
    json += "\"unresolved_call_sites\":" + std::to_string(state.unresolvedIndirectCallSites) + ",";
    json += "\"candidate_cap_hit_sites\":" + std::to_string(state.indirectCandidateCapHitSites);
    json += "},";
    json += "\"path\":[";

    bool first = true;
    for (APIPath *node : orderedNodes) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += nodeToJson(*node);
    }

    json += "]}";
    return json;
}

std::vector<std::pair<std::string, std::string>> analyzeRootCall(
    const AnalyzerContext &ctx,
    Function &function,
    CallBase &rootCall,
    const std::string &rootName,
    const ResolvedCallTargets &rootTargets,
    const FunctionOrderMap &orderByFunction,
    std::clock_t fileStartTime,
    std::clock_t functionStartTime
) {
    // 以单个 root call 为起点，恢复一条 seed-centric API context 记录。
    if (rootName.empty()) {
        return {};
    }

    RootAnalysisState state;
    SourceLocation functionLocation = resolveFunctionLocation(ctx, function);
    state.fileName = functionLocation.file;
    state.functionName = function.getName().str();
    state.apiName = rootName;
    state.fileStartTime = fileStartTime;
    state.functionStartTime = functionStartTime;
    state.instructionStartTime = std::clock();
    if (rootTargets.isIndirect) {
        if (rootTargets.candidateCapHit) {
            ++state.indirectCandidateCapHitSites;
            state.warnings.insert("indirect_call_candidate_cap_hit");
        }
        if (rootTargets.unresolved) {
            ++state.unresolvedIndirectCallSites;
            state.warnings.insert("indirect_call_unresolved");
        } else {
            ++state.resolvedIndirectCallSites;
        }
    }

    auto orderIt = orderByFunction.find(&function);
    if (orderIt == orderByFunction.end()) {
        return {};
    }

    std::unique_ptr<APIPath> rootNode(makeOperationPath(ctx, function, rootCall, rootName, {}, orderIt->second, state));
    if (!rootNode) {
        return {};
    }
    rootNode->callKind = rootTargets.isIndirect ? "indirect" : "direct";
    rootNode->unresolvedIndirect = rootTargets.isIndirect && rootTargets.unresolved;
    for (Function *callee : rootTargets.callees) {
        if (callee != nullptr) {
            rootNode->resolvedCallees.push_back(callee->getName().str());
        }
    }

    RelateMap frvSet;
    RelateMap brvSet;
    RelateMap trackedSet;
    VisitMap visitBlocks;
    std::set<APIPath *> apiList;

    apiList.insert(rootNode.get());
    frvSet[&rootCall].insert(0);
    rootNode->parameter.insert(0);
    trackedSet[&rootCall].insert(0);

    for (unsigned index = 0; index < rootCall.arg_size(); ++index) {
        const int parameter = static_cast<int>(index) + 1;
        rootNode->parameter.insert(parameter);
        trackedSet[&rootCall].insert(parameter);
        findForwardRelateVariable(rootCall.getArgOperand(index), frvSet, trackedSet, parameter, ctx, state);
    }
    findBackwardRelateVariable(frvSet, brvSet, ctx, state);
    if (state.timedOut) {
        return {};
    }

    BasicBlock *entryBlock = &function.getEntryBlock();
    state.expansionStack.push_back(&function);
    findRelateOperation(
        entryBlock,
        brvSet,
        &rootCall,
        rootNode.get(),
        nullptr,
        visitBlocks,
        apiList,
        trackedSet,
        ctx,
        function,
        orderByFunction,
        nullptr,
        state
    );
    state.expansionStack.pop_back();
    if (state.timedOut) {
        releaseAPIPath(apiList, rootNode.get());
        return {};
    }

    clearEmptyAPIPath(apiList);
    std::vector<APIPath *> orderedNodes = orderedNonEmptyNodes(apiList);
    if (orderedNodes.empty()) {
        releaseAPIPath(apiList, rootNode.get());
        return {};
    }

    if (functionLocation.file.empty()) {
        functionLocation.file = rootNode->file;
    }

    const std::string recordJson = recordToJson(
        functionLocation.file,
        function.getName().str(),
        functionLocation.line,
        *rootNode,
        orderedNodes,
        state
    );
    releaseAPIPath(apiList, rootNode.get());

    if (state.timedOut) {
        return {};
    }

    const int parameterArity = positiveParamCount(rootNode->parameter);
    const std::string bucket = sanitizeBucketName(rootNode->name) + "+" + std::to_string(parameterArity);
    return {{bucket, recordJson}};
}

std::vector<std::pair<std::string, std::string>> analyzeModule(
    const AnalyzerContext &ctx,
    Module &module
) {
    // 扫描模块内所有 call 指令，把每个 root call 分析成输出记录。
    std::vector<std::pair<std::string, std::string>> results;
    const std::clock_t fileStartTime = std::clock();
    FunctionOrderMap orderByFunction;

    for (Function &function : module) {
        if (function.empty()) {
            continue;
        }

        OrderMap orderByInst;
        size_t order = 0;
        for (BasicBlock &block : function) {
            for (Instruction &instruction : block) {
                orderByInst[&instruction] = order++;
            }
        }
        orderByFunction.emplace(&function, std::move(orderByInst));
    }

    for (Function &function : module) {
        if (function.empty()) {
            continue;
        }

        const std::clock_t functionStartTime = std::clock();
        for (BasicBlock &block : function) {
            for (Instruction &instruction : block) {
                auto *call = dyn_cast<CallBase>(&instruction);
                if (call == nullptr) {
                    continue;
                }
                const ResolvedCallTargets rootTargets = resolvePotentialCallees(*call);
                if ((!rootTargets.isIndirect && rootTargets.callees.empty()) ||
                    (rootTargets.isIndirect && rootTargets.unresolved)) {
                    continue;
                }
                const std::string rootName = displayCallName(*call, rootTargets);
                if (rootName.empty()) {
                    continue;
                }
                std::vector<std::pair<std::string, std::string>> rootResults =
                    analyzeRootCall(ctx, function, *call, rootName, rootTargets, orderByFunction, fileStartTime, functionStartTime);
                results.insert(results.end(), rootResults.begin(), rootResults.end());
            }
        }
    }

    return results;
}

}  // namespace

// 9. 主流程
int main(int argc, char **argv) {
    // 入口只负责加载配置、遍历 bitcode 模块、落盘各 bucket 结果。
    cl::ParseCommandLineOptions(argc, argv, "LLVM API-level analyzer\n");

    AnalyzerContext ctx;
    ctx.projectId = ProjectId.getValue();
    ctx.repoRoot = fs::path(RepoPath.getValue()).lexically_normal();
    ctx.outputRoot = fs::path(OutputRoot.getValue()).lexically_normal();
    ctx.timeoutLog = ctx.outputRoot.parent_path() / "timeout";
    ctx.maxCrossFunctionDepth = parsePositiveEnvOrDefault(
        "LLVM_API_ANALYZER_MAX_CROSS_FUNCTION_DEPTH",
        ctx.maxCrossFunctionDepth
    );
    loadHelperBlacklist(ctx);

    Expected<std::vector<SinkRuleSet>> sinkRules = loadSinkTaxonomy(fs::path(SinkConfig.getValue()));
    if (!sinkRules) {
        errs() << toString(sinkRules.takeError()) << "\n";
        return 1;
    }
    ctx.sinkRules = std::move(*sinkRules);

    if (!ensureDirectory(ctx.outputRoot)) {
        errs() << "failed to create output root: " << OutputRoot << "\n";
        return 1;
    }

    const std::vector<std::string> bitcodePaths = readBitcodePaths(fs::path(BitcodeList.getValue()));
    if (bitcodePaths.empty()) {
        errs() << "bc.list is empty: " << BitcodeList << "\n";
        return 1;
    }

    for (size_t moduleIndex = 0; moduleIndex < bitcodePaths.size(); ++moduleIndex) {
        LLVMContext llvmContext;
        SMDiagnostic error;
        std::unique_ptr<Module> module = parseIRFile(bitcodePaths[moduleIndex], error, llvmContext);
        if (module == nullptr) {
            errs() << "error loading bitcode: " << bitcodePaths[moduleIndex] << "\n";
            error.print(argv[0], errs());
            return 1;
        }

        const std::vector<std::pair<std::string, std::string>> records = analyzeModule(ctx, *module);
        for (const auto &record : records) {
            const fs::path bucketPath = ctx.outputRoot / record.first;
            if (!ensureDirectory(bucketPath)) {
                errs() << "failed to create bucket: " << bucketPath.generic_string() << "\n";
                return 1;
            }
            std::ofstream handle(bucketPath / std::to_string(moduleIndex), std::ios::app);
            handle << record.second << "\n";
        }
    }

    return 0;
}
