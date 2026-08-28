[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([string]$Message)
    $failures.Add($Message)
}

$markdownFiles = Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Filter '*.md' |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

foreach ($file in $markdownFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    $fenceCount = [regex]::Matches($text, '(?m)^```').Count
    if (($fenceCount % 2) -ne 0) {
        Add-Failure "unclosed Markdown fence: $($file.FullName)"
    }

    $links = [regex]::Matches($text, '\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)')
    foreach ($match in $links) {
        $target = $match.Groups[1].Value.Split('#')[0]
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }
        $decodedTarget = [uri]::UnescapeDataString($target)
        $resolved = Join-Path $file.DirectoryName $decodedTarget
        if (-not (Test-Path -LiteralPath $resolved)) {
            Add-Failure "missing local link: $($file.FullName) -> $target"
        }
    }
}

$diagramPath = Join-Path $repoRoot 'docs/architecture-v5/13-architecture-diagrams.md'
$wikiDiagramPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/diagrams.md'
$diagramText = Get-Content -Raw -LiteralPath $diagramPath
$wikiDiagramText = Get-Content -Raw -LiteralPath $wikiDiagramPath
$mermaidPattern = '(?ms)^```mermaid\s*(.*?)^```'
$diagramBlocks = [regex]::Matches($diagramText, $mermaidPattern) |
    ForEach-Object { $_.Groups[1].Value.Trim() }
$wikiDiagramBlocks = [regex]::Matches($wikiDiagramText, $mermaidPattern) |
    ForEach-Object { $_.Groups[1].Value.Trim() }

if ($diagramBlocks.Count -ne $wikiDiagramBlocks.Count) {
    Add-Failure "Mermaid block count differs: main=$($diagramBlocks.Count), wiki=$($wikiDiagramBlocks.Count)"
} elseif ((Compare-Object $diagramBlocks $wikiDiagramBlocks).Count -ne 0) {
    Add-Failure 'Mermaid blocks differ between the canonical diagram and Wiki copy'
}

$declaredCount = "Mermaid 블록 $($diagramBlocks.Count)개"
if (-not $diagramText.Contains($declaredCount)) {
    Add-Failure "canonical diagram count text is not '$declaredCount'"
}
if (-not $wikiDiagramText.Contains($declaredCount)) {
    Add-Failure "Wiki diagram count text is not '$declaredCount'"
}

$activeContractPaths = @(
    (Join-Path $repoRoot 'docs/architecture-v5'),
    (Join-Path $repoRoot 'docs/review')
)
$forbiddenPatterns = @('RepositorySnapshot', 'snapshot_id', 'deterministic Gate', 'Gate는 규칙 기반 서비스', 'ReportDraft.human_review_state', 'human_review_state:')
foreach ($path in $activeContractPaths) {
    $files = Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.md'
    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($pattern in $forbiddenPatterns) {
            if ($text.Contains($pattern)) {
                Add-Failure "forbidden repository snapshot contract '$pattern': $($file.FullName)"
            }
        }
    }
}

$contractPath = Join-Path $repoRoot 'docs/architecture-v5/08-lightweight-data-contracts.md'
$contractText = Get-Content -Raw -LiteralPath $contractPath
$requiredContractNames = @(
    'WorkExecutionState:',
    'WorkAttempt:',
    'StateTransition:',
    'TransitionCommit:',
    'work_id:',
    'work_generation:',
    'dedupe_key:',
    'state_version:',
    'active_attempt_id:',
    'last_transition_ref:',
    'last_transition_commit_ref:'
)
foreach ($name in $requiredContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4-02 contract name: $name"
    }
}

$transitionCommitBlock = [regex]::Match($contractText, '(?ms)^TransitionCommit:\s*(.*?)^```').Groups[1].Value
$requiredTransitionCommitFields = @(
    'output_refs:',
    'gap_ids:',
    'error_ids:'
)
foreach ($field in $requiredTransitionCommitFields) {
    if (-not $transitionCommitBlock.Contains($field)) {
        Add-Failure "missing TransitionCommit atomic field: $field"
    }
}

$requiredStateRows = @(
    '| `PENDING` | `READY`, `CANCELLED` |',
    '| `READY` | `RUNNING`, `BLOCKED`, `CANCELLED` |',
    '| `RUNNING` | `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` |',
    '| `BLOCKED` | `READY`, `FAILED`, `CANCELLED` |',
    '| `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | 없음 |'
)
foreach ($row in $requiredStateRows) {
    if (-not $contractText.Contains($row)) {
        Add-Failure "missing or changed allowed-transition row: $row"
    }
}

$requiredBindingRules = @(
    '`VERIFICATION`의 `SUCCEEDED`와 `HypothesisProcessState.status=TERMINAL`',
    '`TECHNICAL_GATE`의 `SUCCEEDED`',
    '`RULE_SCOPE_GATE`의 `SUCCEEDED`',
    '`REPORT_DRAFT`의 `SUCCEEDED`와 `ReportProcessState.status=DRAFTED`',
    '`AnalysisRunState.analysis_result_ref`'
)
foreach ($rule in $requiredBindingRules) {
    if (-not $contractText.Contains($rule)) {
        Add-Failure "missing exact output binding rule: $rule"
    }
}

$resultPath = Join-Path $repoRoot 'docs/architecture-v5/07-results-and-observability.md'
$resultText = Get-Content -Raw -LiteralPath $resultPath
$requiredErrorCodes = @(
    'STATE_TRANSITION_INVALID',
    'STATE_VERSION_CONFLICT',
    'ATTEMPT_NOT_ACTIVE',
    'STALE_RESULT',
    'TRANSITION_INCOMPLETE',
    'RECOVERY_FAILED',
    'INTERRUPTED'
)
foreach ($code in $requiredErrorCodes) {
    if (-not $resultText.Contains($code)) {
        Add-Failure "missing R4-02 error code: $code"
    }
}

$securityPath = Join-Path $repoRoot 'docs/architecture-v5/10-security-boundaries.md'
$securityText = Get-Content -Raw -LiteralPath $securityPath
$negativeScenarioMarkers = @(
    '같은 가설 검증 요청이 동시에 두 번 도착',
    'retry 전 attempt 결과가 새 attempt보다 늦게 도착',
    '다른 `workspace_id` 또는 `commit_id` 결과가 합류',
    '가설·분석 취소 뒤 결과가 도착',
    'Technical 보완 전 revision이 Rule Scope Gate나 Reporter로 전달',
    '결과 record만 저장되고 종료 상태가 갱신되지 않음',
    '종료 상태만 있고 output record가 없음',
    '허용되지 않은 provider/model failover',
    'crash 뒤 같은 요청이 다시 들어옴',
    'retry·Gate `REVISE`·chaining이 한도를 넘음',
    '`PARTIAL` 결과에 gap·오류 설명이 없음',
    '분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음',
    '`COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁'
)
foreach ($marker in $negativeScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-02 negative scenario: $marker"
    }
}

$requiredR403ContractNames = @(
    'ActionRequest:',
    'ActionCheck:',
    'ActionDecision:',
    'action_id:',
    'decision_id:',
    'action_decision_ref:',
    'use_status:',
    'HumanReviewPacket:',
    'HumanReviewDecision:',
    'review_packet_id:',
    'review_decision_id:',
    'reviewer_identity_ref:',
    'approved_report_refs:',
    'disclosure_targets:'
)
foreach ($name in $requiredR403ContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4-03 contract name: $name"
    }
}

$requiredActionTypes = @(
    'REGISTER_WORK',
    'CHANGE_WORK_STATE',
    'START_ATTEMPT',
    'CANCEL_WORK',
    'READ_CODE',
    'RUN_TOOL',
    'CALL_LLM',
    'FETCH_POLICY',
    'RUN_SANDBOX',
    'SAVE_RESULT',
    'CALL_TECHNICAL_GATE',
    'CALL_RULE_SCOPE_GATE',
    'CREATE_REPORT_DRAFT',
    'PREPARE_HUMAN_REVIEW',
    'SAVE_HUMAN_DECISION',
    'EXTERNAL_DISCLOSURE'
)
$actionRequestBlock = [regex]::Match($contractText, '(?ms)^ActionRequest:\s*(.*?)^ActionCheck:').Groups[1].Value
foreach ($actionType in $requiredActionTypes) {
    if (-not $actionRequestBlock.Contains($actionType)) {
        Add-Failure "missing R4-03 action type: $actionType"
    }
}

$requiredActionChecks = @(
    'SCHEMA',
    'AUTHORITY',
    'IDENTITY',
    'REVISION',
    'STATE',
    'BUDGET',
    'TOOL',
    'FILE_PATH',
    'SANDBOX',
    'PROVIDER',
    'SESSION',
    'GATE_ORDER',
    'REPORT_READY',
    'REDACTION',
    'DISCLOSURE'
)
$actionCheckBlock = [regex]::Match($contractText, '(?ms)^ActionCheck:\s*(.*?)^ActionDecision:').Groups[1].Value
foreach ($check in $requiredActionChecks) {
    if (-not $actionCheckBlock.Contains($check)) {
        Add-Failure "missing R4-03 ActionCheck: $check"
    }
}

$requiredAuthorityErrors = @(
    'AUTHORITY_DENIED',
    'ACTION_NOT_ALLOWED',
    'GATE_ORDER_INVALID',
    'REPORT_NOT_READY',
    'TOOL_NOT_ALLOWED',
    'FILE_ACCESS_DENIED',
    'SANDBOX_POLICY_DENIED',
    'PROVIDER_PROFILE_DENIED',
    'DISCLOSURE_DENIED',
    'UNTRUSTED_INSTRUCTION'
)
foreach ($code in $requiredAuthorityErrors) {
    if (-not $resultText.Contains($code)) {
        Add-Failure "missing R4-03 authority error code: $code"
    }
}

$authorityScenarioMarkers = @(
    'Orchestration이 `TRUE`를 저장하려 함',
    'Hypothesis Agent가 final verdict를 출력',
    'Technical Gate가 Verification verdict를 바꾸려 함',
    'Technical Gate 없이 Rule Scope Gate 호출',
    'Rule Scope Gate 없이 Reporter 호출',
    '공식 정책이 없는데 `ALLOW` 출력',
    'repository prompt가 Sandbox network를 열라고 함',
    'LLM이 workspace 밖 파일을 요청',
    '허용하지 않은 provider/model로 silent failover',
    '인증 실패를 `FALSE`로 저장하려 함',
    'Reporter가 새 공격 경로를 확정',
    'LLM이 `HumanReviewDecision` 형식의 승인을 출력',
    'Agent가 외부 공개 action을 요청',
    '사람이 다른 packet·과거 revision의 승인을 재사용',
    'redaction 실패 PoC를 사람 또는 외부로 전달'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$orchestrationPath = Join-Path $repoRoot 'docs/architecture-v5/03-agent-roles-and-orchestration.md'
$orchestrationText = Get-Content -Raw -LiteralPath $orchestrationPath
$gatePath = Join-Path $repoRoot 'docs/architecture-v5/05-llm-gate-and-reporting.md'
$gateText = Get-Content -Raw -LiteralPath $gatePath
$requiredAuthorityRules = @(
    '## 역할별 권한 경계',
    '## action 요청과 실행',
    'final VerificationResult + CWELabel',
    '-> Technical Evidence Gate',
    '-> Rule Scope Impact Gate',
    'HumanReviewPacket',
    'HumanReviewDecision'
)
foreach ($rule in $requiredAuthorityRules) {
    if (-not ($orchestrationText.Contains($rule) -or $gateText.Contains($rule) -or $contractText.Contains($rule))) {
        Add-Failure "missing R4-03 authority rule: $rule"
    }
}

$savedErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$gitCheck = & git -C $repoRoot diff --check 2>&1
$gitCheckExitCode = $LASTEXITCODE
$ErrorActionPreference = $savedErrorAction
if ($gitCheckExitCode -ne 0) {
    Add-Failure "git diff --check failed: $($gitCheck -join [Environment]::NewLine)"
}

Write-Output "Markdown files: $($markdownFiles.Count)"
Write-Output "Mermaid blocks: $($diagramBlocks.Count) canonical / $($wikiDiagramBlocks.Count) Wiki"
Write-Output "R4-02 required contract names: $($requiredContractNames.Count)"
Write-Output "R4-02 TransitionCommit atomic fields: $($requiredTransitionCommitFields.Count)"
Write-Output "R4-02 exact output bindings: $($requiredBindingRules.Count)"
Write-Output "R4-02 required error codes: $($requiredErrorCodes.Count)"
Write-Output "R4-02 negative scenarios: $($negativeScenarioMarkers.Count)"
Write-Output "R4-03 required contract names: $($requiredR403ContractNames.Count)"
Write-Output "R4-03 action types: $($requiredActionTypes.Count)"
Write-Output "R4-03 ActionCheck types: $($requiredActionChecks.Count)"
Write-Output "R4-03 authority errors: $($requiredAuthorityErrors.Count)"
Write-Output "R4-03 authority scenarios: $($authorityScenarioMarkers.Count)"
Write-Output "R4-03 authority rules: $($requiredAuthorityRules.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
