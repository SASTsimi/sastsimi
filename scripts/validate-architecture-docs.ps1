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
if (-not $diagramText.Contains('RUNNING --> READY: immediate dynamic auto retry')) {
    Add-Failure 'canonical state diagram is missing the DYNAMIC_REPRO immediate auto-retry transition'
}

$activeContractPaths = @(
    (Join-Path $repoRoot 'docs/architecture-v5'),
    (Join-Path $repoRoot 'docs/review'),
    (Join-Path $repoRoot 'docs/governance')
)
$forbiddenPatterns = @(
    'RepositorySnapshot',
    'snapshot_id',
    'deterministic Gate',
    'Gate는 규칙 기반 서비스',
    'ReportDraft.human_review_state',
    'human_review_state:',
    'HumanReviewPacket',
    'HumanReviewState',
    'HumanReviewDecision',
    'HUMAN_REVIEWER',
    'PREPARE_HUMAN_REVIEW',
    'SAVE_HUMAN_DECISION',
    'EXTERNAL_DISCLOSURE',
    'PACKET_READY',
    'DISCLOSURE_DENIED',
    'review_packet_id',
    'review_decision_id',
    'reviewer_identity_ref',
    'approved_report_refs',
    'disclosure_targets',
    'NEED_MORE_VALIDATION',
    'WITHHOLD',
    'decision: DISCLOSE',
    'human_reviews'
)
foreach ($path in $activeContractPaths) {
    $files = Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.md'
    foreach ($file in $files) {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($pattern in $forbiddenPatterns) {
            if ($text.Contains($pattern)) {
                Add-Failure "forbidden obsolete active contract '$pattern': $($file.FullName)"
            }
        }
    }
}
foreach ($filePath in @((Join-Path $repoRoot 'README.md'), (Join-Path $repoRoot 'docs/GLOSSARY.md'))) {
    $text = Get-Content -Raw -LiteralPath $filePath
    foreach ($pattern in $forbiddenPatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "forbidden obsolete active contract '$pattern': $filePath"
        }
    }
}

# Current documentation must not reintroduce the pre-ADR-005 Primitive model.
# Decision records are historical and are intentionally excluded from this scan.
$activeUnifiedPrimitiveFiles = @(
    (Get-Item -LiteralPath (Join-Path $repoRoot 'README.md')),
    (Get-Item -LiteralPath (Join-Path $repoRoot 'docs/GLOSSARY.md')),
    (Get-Item -LiteralPath (Join-Path $repoRoot 'docs/DOCUMENT_GUIDE.md'))
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/governance') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/review') -Recurse -File -Filter '*.md' |
        Where-Object { $_.FullName -notmatch '[\\/]decisions[\\/]' }
)
$obsoleteUnifiedPrimitivePatterns = @(
    'Gate-qualified',
    'active_required_refs',
    'active_provided_refs',
    'HeldHypothesis',
    'ConfirmedCapability',
    'root_hypothesis_id',
    'chain_depth',
    'bounded_stop_reason',
    'required_preconditions',
    'commit-time Primitive index',
    'PROVIDED Primitive',
    'REQUIRED Primitive'
)
foreach ($file in $activeUnifiedPrimitiveFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($pattern in $obsoleteUnifiedPrimitivePatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "obsolete pre-ADR-005 Primitive term '$pattern': $($file.FullName)"
        }
    }
}

# Current documentation must not restore the pre-ADR-007 Runner/step-list contract.
# Historical ADRs and superseded design plans are intentionally excluded.
$obsoleteR7SchemaPatterns = @(
    'runner_invoked:',
    'steps_ref:',
    'environment_created:',
    'ReproductionStep:',
    'mode: LIMITED_REPRO | FULL_REPRO',
    'requested_by=SANDBOX',
    'failure_reason=POLICY_BLOCKED'
)
foreach ($file in $activeUnifiedPrimitiveFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($pattern in $obsoleteR7SchemaPatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "obsolete pre-ADR-007 R7 schema term '$pattern': $($file.FullName)"
        }
    }
}

$contractPath = Join-Path $repoRoot 'docs/architecture-v5/08-lightweight-data-contracts.md'
$contractText = Get-Content -Raw -LiteralPath $contractPath
$overviewPath = Join-Path $repoRoot 'docs/architecture-v5/01-system-overview.md'
$overviewText = Get-Content -Raw -LiteralPath $overviewPath
$verificationPath = Join-Path $repoRoot 'docs/architecture-v5/04-verification-and-dynamic-reproduction.md'
$verificationText = Get-Content -Raw -LiteralPath $verificationPath
$activeDebateFiles = @(
    (Get-Item -LiteralPath (Join-Path $repoRoot 'README.md'))
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/governance') -Recurse -File -Filter '*.md'
)
$activeDebateText = ($activeDebateFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
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

$requiredDebateContractNames = @(
    'EvidenceAgentResult:',
    'parent_work_ref:',
    'parent_work_id:',
    'evidence_work_id:',
    'verification_generation:',
    'llm_call_id:',
    'debate_input_hash:',
    'pro_evidence_ref:',
    'con_evidence_ref:'
)
foreach ($name in $requiredDebateContractNames) {
    if (-not $contractText.Contains($name)) {
        Add-Failure "missing R4 Pro/Con join contract name: $name"
    }
}

$workExecutionBlock = [regex]::Match($contractText, '(?ms)^WorkExecutionState:\s*(.*?)^WorkAttempt:').Groups[1].Value
if (-not $workExecutionBlock.Contains('parent_work_ref:')) {
    Add-Failure 'WorkExecutionState is missing parent_work_ref'
}
if (-not $contractText.Contains('`PRO_EVIDENCE | CON_EVIDENCE | DYNAMIC_REPRO | CWE_LABEL`에서는 필수')) {
    Add-Failure 'Verification child work is not bound to the current Verification parent'
}

$evidenceAgentResultBlock = [regex]::Match($contractText, '(?ms)^EvidenceAgentResult:\s*(.*?)^CandidateRef:').Groups[1].Value
$requiredEvidenceAgentResultFields = @(
    'role:',
    'parent_work_id:',
    'evidence_work_id:',
    'verification_generation:',
    'llm_call_id:',
    'debate_input_hash:',
    'evidence:',
    'summary:',
    'limitations:'
)
foreach ($field in $requiredEvidenceAgentResultFields) {
    if (-not $evidenceAgentResultBlock.Contains($field)) {
        Add-Failure "EvidenceAgentResult is missing field: $field"
    }
}

$verificationResultBlock = [regex]::Match($contractText, '(?ms)^VerificationResult:\s*(.*?)^```').Groups[1].Value
$requiredVerificationDebateFields = @(
    'debate_input_hash:',
    'pro_evidence_ref:',
    'con_evidence_ref:'
)
foreach ($field in $requiredVerificationDebateFields) {
    if (-not $verificationResultBlock.Contains($field)) {
        Add-Failure "VerificationResult is missing Pro/Con join field: $field"
    }
}

$cweLabelBlock = [regex]::Match($contractText, '(?ms)^CWELabel:\s*(.*?)^```').Groups[1].Value
$requiredCweLabelFields = @(
    'verification_result_ref:',
    'verification_generation:',
    'cwe_labeling_work_id:',
    'llm_call_id:',
    'primary:',
    'alternatives:',
    'taxonomy_version:',
    'rationale:',
    'evidence_refs:',
    'uncertainty:'
)
foreach ($field in $requiredCweLabelFields) {
    if (-not $cweLabelBlock.Contains($field)) {
        Add-Failure "CWELabel is missing field: $field"
    }
}

$requiredCweLabelContractMarkers = @(
    '`CWELabel`의 logical producer/runtime role은 `CWE_LABELING`, R1~R8 실제 업무 owner는 R5-01이다.',
    '`CWE_LABEL`은 이 역할을 실행하는 `WorkExecutionState.work_type` 이름이다.',
    'primary·alternatives가 그대로여도 새 Verification을 가리키는 새 revision이 필요하다.',
    '과거 label은 overwrite하지 않고 감사 이력으로 보존하지만 새 `CWE_LABEL` work나 Gate의 current input으로 재사용하지 않는다.',
    'current label은 current final TRUE를 input으로 가진 유일한 `CWE_LABEL` work가 `SUCCEEDED`이고 그 work의 유일한 `output_refs`가 가리키는 exact revision이다.',
    '`CWELabel.verification_result_ref`와 exact match해야 한다.',
    'CWE labeling 실패·timeout·provider 인증 오류는 Verification을 `FALSE | HOLD`로 바꾸지 않으며',
    'Technical Gate는 CWE 정합성을 검토할 뿐 `CWELabel`을 생성·수정·덮어쓰지 않는다.',
    '`CWE_LABEL`의 `SUCCEEDED`, exact `CWELabel` 저장과 그 하나뿐인 `output_refs`는 같은 `COMMITTED` `TransitionCommit`으로 확정한다.',
    'R5-01 `CWE_LABELING`의 `CALL_LLM`은 current `CWE_LABEL` work의 active attempt에서만 허용한다.',
    'R5-01 `CWE_LABELING`은 exact `CWELabel`',
    '`CWELabel.llm_call_id`는 바로 이 성공한 CWE 호출의 `llm_call_id`와 같아야 한다.',
    '`AnalysisRunResult.cwe_label_refs`에는 각 current final TRUE Verification에 대응하는 current `CWELabel`만 가설별로 하나씩 넣는다.'
)
foreach ($marker in $requiredCweLabelContractMarkers) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing or weakened R5-01 CWE labeling contract: $marker"
    }
}

$requiredDebateContractMarkers = @(
    '운영 `purpose=PRODUCTION`은 항상 `verification_mode=ALWAYS_DEBATE`이며 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref`가 모두 필수다',
    '평가용 `BASIC` 또는 trigger가 발생하지 않은 `CONDITIONAL_DEBATE`는 세 필드를 모두 `null`',
    'final Verification 합성용 `LLMCallSpec.context_refs`와 `SAVE_RESULT.input_refs`에는 이 두 exact result reference를 각각 한 번 포함한다',
    '`pro_evidence_result -> EvidenceAgentResult(role=PRO) -> PRO`',
    '`con_evidence_result -> EvidenceAgentResult(role=CON) -> CON`',
    '`result_kind=pro_evidence_result | con_evidence_result`',
    '`LLMInvocationResult.parsed_output_ref` 및 `LLMInvocationLog.parsed_output_ref`',
    '각 record의 새 MAJOR schema로 배포한다',
    '운영 Pro/Con 자식 중 하나가 재시도 가능한 오류로 `BLOCKED`가 되면 부모 `VERIFICATION` work도 `BLOCKED`',
    '먼저 그 자식 work의 `FAILED`를 자기 `COMMITTED` `TransitionCommit`으로 확정',
    '부모 work의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 기존 Verification 실패 atomic 경계로 함께 확정',
    'trusted prompt builder',
    '`CROSS_ROLE_INPUT_DENIED`'
)
foreach ($marker in $requiredDebateContractMarkers) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing or weakened R4 Pro/Con join rule: $marker"
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
    '| `RUNNING` | `READY`, `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` |',
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
    '`DYNAMIC_REPRO`의 종료 transition',
    '`CWE_LABEL`의 `SUCCEEDED`, exact `CWELabel` 저장',
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

$reviewRemediationPatterns = @(
    @{
        Name = 'dynamic state requires request and uses an exact result pointer when a result exists'
        Pattern = '(?s)동적 재현을 요청하면 `DynamicReproductionState.request_ref`.*?current generation의 exact `DynamicReproductionRequest`.*?`SUCCEEDED \| PARTIAL \| BLOCKED \| FAILED \| CANCELLED`에는 Reproduction Session Manager가 확정한 exact `DynamicReproductionResult\.record_id`가 필수.*?Agent 호출 전 정책 차단도 Session Manager가 최소 `AgentLog`와 결과'
    },
    @{
        Name = 'dynamic PARTIAL uses structured limitations without fake errors'
        Pattern = '(?s)`DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult\(status=PARTIAL, failure_category=NONE, failure_reason=null\)`.*?`hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상.*?억지로 `error_ids`나 `gap_ids`로 만들지 않는다'
    },
    @{
        Name = 'dynamic autonomous retry is distinct from external blocking'
        Pattern = '(?s)R7이 스스로 해결할 수 있는 command·PoC·환경 조정은 `BLOCKED` 사유가 아니며.*?`RUNNING -> READY -> RUNNING` 자동 retry.*?외부 조건이 해결되면 같은 `work_id`에서 새 `attempt_id`'
    },
    @{
        Name = 'dynamic cancellation result is atomically bound and late output is stale'
        Pattern = '(?s)`DYNAMIC_REPRO` 취소 전이.*?`DynamicReproductionResult\(status=CANCELLED\)`.*?같은 atomic transition.*?이미 `CANCELLED`가 확정된 뒤 늦게 도착한 output.*?연결하지 않는다'
    },
    @{
        Name = 'exact Technical and Rule Scope domain input sets'
        Pattern = '(?s)Gate domain input set.*?`TECHNICAL_GATE`에서는 `VerificationResult`와 `CWELabel` reference가 정확한 domain input set.*?`RULE_SCOPE_GATE`에서는 `VerificationResult`, `TechnicalEvidenceReview`, `CWELabel`과 존재하는 `ProgramPolicyRecord` reference가 정확한 domain input set'
    },
    @{
        Name = 'Gate result references match the frozen work inputs'
        Pattern = '(?s)`TechnicalEvidenceReview` 안의 `verification_result_ref`와 `cwe_label_ref`.*?Technical Gate work의 domain input 두 개와 각각 exact match.*?`RuleScopeImpactReview` 안의 `verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_record_ref`.*?Rule Scope Gate work의 domain input set과 exact match'
    },
    @{
        Name = 'REVISE creates a new work while retry keeps the same work'
        Pattern = '(?s)`REVISE`는 일반 retry나 resume이 아니다\..*?같은 hypothesis의 ACTIVE `VerificationAssignment` owner.*?새 `WorkExecutionState\(work_type=VERIFICATION\)`.*?새 `VerificationResult`.*?새 `CWELabel` revision.*?(?:새 Gate 작업은 )?달라진 `input_refs`, `input_hash`, `dedupe_key`, `work_id`.*?`attempt_number=1`, `trigger=INITIAL`.*?일반 retry.*?같은 `work_id`.*?`trigger=RETRY`'
    },
    @{
        Name = 'contradictory ALLOW becomes INVALID_OUTPUT and blocks Reporter'
        Pattern = '(?s)Gate LLM 출력.*?`LLMInvocationResult.status=INVALID_OUTPUT`.*?`AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`.*?`WorkAttempt.status=FAILED`.*?`RuleScopeImpactReview`를 `COMMITTED`하지 않는다.*?Reporter 호출.*?금지'
    }
)
foreach ($rule in $reviewRemediationPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #26 review remediation rule: $($rule.Name)"
    }
}

$resultPath = Join-Path $repoRoot 'docs/architecture-v5/07-results-and-observability.md'
$resultText = Get-Content -Raw -LiteralPath $resultPath
$staticPath = Join-Path $repoRoot 'docs/architecture-v5/02-static-fact-layer.md'
$staticText = Get-Content -Raw -LiteralPath $staticPath
$commonWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/common-contracts.md'
$commonWikiText = Get-Content -Raw -LiteralPath $commonWikiPath
$requiredErrorCodes = @(
    'STATE_TRANSITION_INVALID',
    'STATE_VERSION_CONFLICT',
    'ATTEMPT_NOT_ACTIVE',
    'STALE_RESULT',
    'TRANSITION_INCOMPLETE',
    'RECOVERY_FAILED',
    'INTERRUPTED',
    'CROSS_ROLE_INPUT_DENIED'
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
    '`PARTIAL` 결과에 누락 설명이 없음',
    'PoC 생성·환경 구성·실행 실패를 `FALSE | HOLD`로 변환함',
    '동적 종료 결과와 work·전문 상태 pointer가 다름',
    '분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음',
    '`COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁',
    '모순된 `ALLOW`가 Reporter 호출을 요청',
    'Pro 또는 Con prompt·context·조회·tool 결과에 상대 역할 output을 넣음',
    'final Verification에 Pro 또는 Con exact result reference가 빠짐',
    'Pro·Con 결과의 부모·generation·공통 입력 hash가 서로 다름',
    'Pro/Con child가 `BLOCKED`인데 부모 Verification은 `RUNNING`으로 계속됨',
    'Pro/Con child가 최종 실패했는데 부모나 가설을 계속 진행'
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
    'DynamicReproductionRequest:',
    'EnvironmentRequirements:',
    'ReproductionPlan:',
    'EnvironmentRecipe:',
    'SandboxEnvironment:',
    'PlanIssueItem:',
    'SandboxPolicyDecision:',
    'CleanupResult:',
    'AgentLogEvent:',
    'AgentLog:',
    'PoCCandidate:',
    'PoCBundle:',
    'DynamicReproductionResult:',
    'LLMCallSpec:',
    'action_id:',
    'decision_id:',
    'action_decision_ref:',
    'use_status:'
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
    'REQUEST_DYNAMIC_REPRO',
    'RUN_SANDBOX',
    'SAVE_RESULT',
    'CALL_TECHNICAL_GATE',
    'CALL_RULE_SCOPE_GATE',
    'CREATE_REPORT_DRAFT'
)
$actionRequestBlock = [regex]::Match($contractText, '(?ms)^ActionRequest:\s*(.*?)^ActionCheck:').Groups[1].Value
$requiredActionRequestFields = @(
    'requester_identity_ref:',
    'input_refs:',
    'dynamic_request_ref:',
    'reproduction_plan_ref:',
    'result_kind:',
    'candidate_result_ref:',
    'llm_call_spec_ref:',
    'provider_profile_ref:',
    'sandbox_profile_ref:'
)
foreach ($field in $requiredActionRequestFields) {
    if (-not $actionRequestBlock.Contains($field)) {
        Add-Failure "missing R4-03 ActionRequest field: $field"
    }
}

$environmentNeedBlock = [regex]::Match($contractText, '(?ms)^EnvironmentNeed:\s*(.*?)^DynamicReproductionRequest:').Groups[1].Value
$dynamicRequestBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionRequest:\s*(.*?)^EnvironmentRequirement:').Groups[1].Value
$environmentRequirementBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirement:\s*(.*?)^EnvironmentRequirements:').Groups[1].Value
$environmentRequirementsBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRequirements:\s*(.*?)^ReproductionPlan:').Groups[1].Value
$reproductionPlanBlock = [regex]::Match($contractText, '(?ms)^ReproductionPlan:\s*(.*?)^EnvironmentRecipe:').Groups[1].Value
$environmentRecipeBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRecipe:\s*(.*?)^EnvironmentCheck:').Groups[1].Value
$environmentCheckBlock = [regex]::Match($contractText, '(?ms)^EnvironmentCheck:\s*(.*?)^SandboxEnvironment:').Groups[1].Value
$sandboxEnvironmentBlock = [regex]::Match($contractText, '(?ms)^SandboxEnvironment:\s*(.*?)^PlanIssueItem:').Groups[1].Value
$planIssueItemBlock = [regex]::Match($contractText, '(?ms)^PlanIssueItem:\s*(.*?)^SandboxPolicyDecision:').Groups[1].Value
$sandboxPolicyDecisionBlock = [regex]::Match($contractText, '(?ms)^SandboxPolicyDecision:\s*(.*?)^CleanupResult:').Groups[1].Value
$cleanupResultBlock = [regex]::Match($contractText, '(?ms)^CleanupResult:\s*(.*?)^AgentLogEvent:').Groups[1].Value
$agentLogEventBlock = [regex]::Match($contractText, '(?ms)^AgentLogEvent:\s*(.*?)^AgentLog:').Groups[1].Value
$agentLogBlock = [regex]::Match($contractText, '(?ms)^AgentLog:\s*(.*?)^PoCCandidate:').Groups[1].Value
$pocCandidateBlock = [regex]::Match($contractText, '(?ms)^PoCCandidate:\s*(.*?)^PoCBundle:').Groups[1].Value
$pocBundleBlock = [regex]::Match($contractText, '(?ms)^PoCBundle:\s*(.*?)^DynamicReproductionResult:').Groups[1].Value
$dynamicResultBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('need_id:', 'kind:', 'description:', 'required:', 'source_refs:')) {
    if (-not $environmentNeedBlock.Contains($field)) {
        Add-Failure "missing EnvironmentNeed field: $field"
    }
}
foreach ($field in @('verification_assignment_ref:', 'verification_generation:', 'hypothesis_ref:', 'purpose:', 'initial_verdict:', 'goal:', 'environment_needs:', 'sandbox_profile_ref:', 'code_refs:', 'static_evidence_refs:', 'pro_evidence_ref:', 'con_evidence_ref:')) {
    if (-not $dynamicRequestBlock.Contains($field)) {
        Add-Failure "missing DynamicReproductionRequest field: $field"
    }
}
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'kind:\s*APP_ROLE \| AUTH \| DATA \| DATABASE \| SERVICE \| FIXTURE \| MOCK \| VERSION \| HEALTH_CHECK',
    'name:\s*string',
    'required:\s*boolean',
    'expected:\s*string \| null',
    'expected_ref:\s*StoredDataRef \| null',
    'alternatives:\s*\[string\]',
    'check_ref:\s*StoredDataRef \| null',
    'secret_ref:\s*StoredDataRef \| null',
    'source_refs:\s*\[StoredDataRef\]'
)) {
    if (-not [regex]::IsMatch($environmentRequirementBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirement field: $fieldPattern"
    }
}
foreach ($fieldPattern in @('meta:\s*RecordMeta', 'request_ref:\s*StoredDataRef', 'items:\s*\[EnvironmentRequirement\]')) {
    if (-not [regex]::IsMatch($environmentRequirementsBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentRequirements field: $fieldPattern"
    }
}
foreach ($field in @('request_ref:', 'purpose:', 'hypothesis_ref:', 'environment_requirements_ref:', 'sandbox_profile_ref:', 'reproduction_goal:', 'strategy_summary:', 'requested_evidence:')) {
    if (-not $reproductionPlanBlock.Contains($field)) {
        Add-Failure "missing ReproductionPlan field: $field"
    }
}
foreach ($field in @('meta:', 'request_ref:', 'environment_requirements_ref:', 'recipe_source_ref:', 'source_refs:', 'base_image_digest:', 'built_image_digest:', 'baseline_recipe_ref:', 'build_disposition:', 'created_at:')) {
    if (-not $environmentRecipeBlock.Contains($field)) {
        Add-Failure "missing EnvironmentRecipe field: $field"
    }
}
foreach ($fieldPattern in @(
    'requirement_id:\s*string',
    'status:\s*MATCH \| MISMATCH \| NOT_CHECKED \| ERROR',
    'actual:\s*string \| null',
    'actual_ref:\s*StoredDataRef \| null',
    'difference:\s*string \| null',
    'evidence_refs:\s*\[StoredDataRef\]',
    'check_result_ref:\s*StoredDataRef \| null'
)) {
    if (-not [regex]::IsMatch($environmentCheckBlock, $fieldPattern)) {
        Add-Failure "missing or invalid EnvironmentCheck field: $fieldPattern"
    }
}
foreach ($fieldPattern in @(
    'meta:\s*RecordMeta',
    'request_ref:\s*StoredDataRef',
    'reproduction_plan_ref:\s*StoredDataRef',
    'environment_recipe_ref:\s*StoredDataRef',
    'requirements_ref:\s*StoredDataRef',
    'container_instance_id:\s*string',
    'container_action:\s*CREATED \| REUSED',
    'container_reason:\s*INITIAL_CLEAN \| NO_RELEVANT_CHANGE \| STATE_CHANGED \| CONFIG_CHANGED \| STATE_UNCERTAIN',
    'previous_environment_ref:\s*StoredDataRef \| null',
    'status:\s*READY \| MISMATCH \| ERROR',
    'checks:\s*\[EnvironmentCheck\]',
    'created_at:\s*timestamp'
)) {
    if (-not [regex]::IsMatch($sandboxEnvironmentBlock, $fieldPattern)) {
        Add-Failure "missing or invalid SandboxEnvironment field: $fieldPattern"
    }
}
foreach ($fieldPattern in @(
    'issue_code:\s*MISSING_INPUT \| CONTRADICTORY_REQUIREMENT \| UNEXECUTABLE_GOAL \| STALE_REFERENCE \| OTHER',
    'status:\s*OPEN \| RESOLVED',
    'message:\s*string',
    'related_refs:\s*\[StoredDataRef\]'
)) {
    if (-not [regex]::IsMatch($planIssueItemBlock, $fieldPattern)) { Add-Failure "missing or invalid PlanIssueItem field: $fieldPattern" }
}
foreach ($field in @('meta:', 'action_decision_ref:', 'request_ref:', 'sandbox_profile_ref:', 'resource_profile_ref:', 'decision:', 'reason_codes:', 'checked_boundary_refs:', 'decided_at:')) {
    if (-not $sandboxPolicyDecisionBlock.Contains($field)) { Add-Failure "missing SandboxPolicyDecision field: $field" }
}
foreach ($field in @('meta:', 'request_ref:', 'environment_refs:', 'resource_refs:', 'status:', 'failure_reason:', 'finished_at:')) {
    if (-not $cleanupResultBlock.Contains($field)) { Add-Failure "missing CleanupResult field: $field" }
}
foreach ($field in @('event_id:', 'sequence:', 'action_id:', 'event_type:', 'actor:', 'environment_ref:', 'environment_recipe_ref:', 'poc_candidate_ref:', 'input_refs:', 'output_refs:', 'exit_code:', 'safe_message:', 'occurred_at:')) {
    if (-not $agentLogEventBlock.Contains($field)) { Add-Failure "missing AgentLogEvent field: $field" }
}
foreach ($field in @('meta:', 'request_ref:', 'events:')) {
    if (-not $agentLogBlock.Contains($field)) {
        Add-Failure "missing AgentLog field: $field"
    }
}
foreach ($field in @('meta:', 'request_ref:', 'reproduction_plan_ref:', 'content_ref:', 'content_digest:', 'created_by_invocation_ref:', 'created_at:')) {
    if (-not $pocCandidateBlock.Contains($field)) { Add-Failure "missing PoCCandidate field: $field" }
}
foreach ($field in @('meta:', 'request_ref:', 'reproduction_plan_ref:', 'environment_recipe_ref:', 'environment_ref:', 'agent_log_ref:', 'candidate_ref:', 'candidate_digest:', 'execution_action_id:', 'evidence_refs:', 'validated_at:')) {
    if (-not $pocBundleBlock.Contains($field)) { Add-Failure "missing PoCBundle field: $field" }
}
foreach ($fieldPattern in @(
    'meta:\s*RecordMeta',
    'action_decision_ref:\s*StoredDataRef \| null',
    'request_ref:\s*StoredDataRef',
    'reproduction_plan_ref:\s*StoredDataRef \| null',
    'purpose:\s*POC_CONFIRMATION \| VERDICT_EVIDENCE',
    'policy_decision_ref:\s*StoredDataRef \| null',
    'agent_invoked:\s*boolean',
    'agent_log_ref:\s*StoredDataRef',
    'environment_recipe_ref:\s*StoredDataRef \| null',
    'environment_ref:\s*StoredDataRef \| null',
    'poc_candidate_ref:\s*StoredDataRef \| null',
    'poc_ref:\s*StoredDataRef \| null',
    'observation_refs:\s*\[StoredDataRef\]',
    'status:\s*SUCCEEDED \| PARTIAL \| FAILED \| BLOCKED \| CANCELLED',
    'failure_category:\s*NONE \| POLICY_BLOCKED \| EXTERNAL_CONFIGURATION \| PLAN \| ENVIRONMENT_SETUP \| DEPENDENCY \| AGENT \| EXECUTION \| OBSERVATION \| TIMEOUT \| RESOURCE_LIMIT \| RETRY_LIMIT \| INTERNAL',
    'failure_reason:\s*string \| null',
    'plan_issues:\s*\[PlanIssueItem\]',
    'hypothesis_outcome:\s*SUPPORTED \| DISPROVED \| INCONCLUSIVE',
    'hypothesis_evidence_refs:\s*\[StoredDataRef\]',
    'hypothesis_disproved:\s*boolean',
    'disproof_evidence_refs:\s*\[StoredDataRef\]',
    'hypothesis_linkage:\s*string',
    'limitations:\s*\[string\]',
    'cleanup_required:\s*boolean',
    'cleanup_status:\s*SUCCEEDED \| FAILED \| NOT_REQUIRED',
    'cleanup_ref:\s*StoredDataRef \| null',
    'started_at:\s*timestamp',
    'finished_at:\s*timestamp',
    'elapsed_ms:\s*integer'
)) {
    if (-not [regex]::IsMatch($dynamicResultBlock, $fieldPattern)) {
        Add-Failure "missing or invalid DynamicReproductionResult field: $fieldPattern"
    }
}
if ($dynamicResultBlock.Contains('environment_requirements_ref:')) {
    Add-Failure 'DynamicReproductionResult must not duplicate environment_requirements_ref; follow reproduction_plan_ref and environment_ref instead'
}
foreach ($actionType in $requiredActionTypes) {
    if (-not $actionRequestBlock.Contains($actionType)) {
        Add-Failure "missing R4-03 action type: $actionType"
    }
    $tableRowPattern = '(?m)^\| `' + [regex]::Escape($actionType) + '`\s*\|'
    $tableRowCount = [regex]::Matches($contractText, $tableRowPattern).Count
    if ($tableRowCount -ne 2) {
        Add-Failure "R4-03 action type must have exactly one required-check row and one requester row: $actionType"
    }
}

$requiredActionCheckBindings = [ordered]@{
    REGISTER_WORK = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    CHANGE_WORK_STATE = 'SCHEMA, AUTHORITY, IDENTITY, STATE'
    START_ATTEMPT = 'SCHEMA, AUTHORITY, STATE, BUDGET'
    CANCEL_WORK = 'SCHEMA, AUTHORITY, IDENTITY, STATE'
    READ_CODE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, BUDGET, FILE_PATH'
    RUN_TOOL = 'SCHEMA, AUTHORITY, REVISION, BUDGET, TOOL, FILE_PATH'
    CALL_LLM = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REDACTION'
    FETCH_POLICY = 'SCHEMA, AUTHORITY, BUDGET, TOOL, REDACTION'
    REQUEST_DYNAMIC_REPRO = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    RUN_SANDBOX = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET'
    SAVE_RESULT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION'
    CALL_TECHNICAL_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CALL_RULE_SCOPE_GATE = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION'
    CREATE_REPORT_DRAFT = 'SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REPORT_READY, REDACTION'
}
foreach ($binding in $requiredActionCheckBindings.GetEnumerator()) {
    $rowPattern = '(?m)^\| `' + [regex]::Escape($binding.Key) + '`\s*\|\s*' + [regex]::Escape($binding.Value) + '\s*\|'
    if ([regex]::Matches($contractText, $rowPattern).Count -ne 1) {
        Add-Failure "wrong R4-03 required checks for action: $($binding.Key)"
    }
}

$requiredActionRequesterBindings = [ordered]@{
    REGISTER_WORK = 'ORCHESTRATION, VERIFICATION, RECOVERY'
    CHANGE_WORK_STATE = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    START_ATTEMPT = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    CANCEL_WORK = 'ORCHESTRATION, VERIFICATION, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    READ_CODE = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE'
    RUN_TOOL = 'REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR'
    CALL_LLM = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, R7_AGENT'
    FETCH_POLICY = 'POLICY_COLLECTOR'
    REQUEST_DYNAMIC_REPRO = 'VERIFICATION'
    RUN_SANDBOX = 'R7_SETUP_AUTOMATION'
    SAVE_RESULT = 'ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, R7_AGENT, R7_SETUP_AUTOMATION, SANDBOX_CONTROLLER, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    CALL_TECHNICAL_GATE = 'VERIFICATION'
    CALL_RULE_SCOPE_GATE = 'VERIFICATION'
    CREATE_REPORT_DRAFT = 'VERIFICATION'
}
foreach ($binding in $requiredActionRequesterBindings.GetEnumerator()) {
    $rowPattern = '(?m)^\| `' + [regex]::Escape($binding.Key) + '`\s*\|\s*' + [regex]::Escape($binding.Value) + '\s*\|\s*$'
    if ([regex]::Matches($contractText, $rowPattern).Count -ne 1) {
        Add-Failure "wrong R4-03 requester authority for action: $($binding.Key)"
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
    'PROVIDER',
    'SESSION',
    'GATE_ORDER',
    'REPORT_READY',
    'REDACTION'
)
$actionCheckBlock = [regex]::Match($contractText, '(?ms)^ActionCheck:\s*(.*?)^ActionDecision:').Groups[1].Value
foreach ($check in $requiredActionChecks) {
    if (-not $actionCheckBlock.Contains($check)) {
        Add-Failure "missing R4-03 ActionCheck: $check"
    }
}

$actionDecisionBlock = [regex]::Match($contractText, '(?ms)^ActionDecision:\s*(.*?)^```').Groups[1].Value
$requiredActionDecisionFields = @('action_ref:', 'required_checks:', 'check_results:', 'checked_state_version:', 'checked_config_refs:', 'valid_until:', 'use_status:', 'used_at:', 'expired_at:', 'expire_reason:', 'outcome_refs:')
foreach ($field in $requiredActionDecisionFields) {
    if (-not $actionDecisionBlock.Contains($field)) {
        Add-Failure "missing R4-03 ActionDecision field: $field"
    }
}

$llmSpecBlock = [regex]::Match($contractText, '(?ms)^LLMCallSpec:\s*(.*?)^LLMInvocationRequest:').Groups[1].Value
$llmRequestBlock = [regex]::Match($contractText, '(?ms)^LLMInvocationRequest:\s*(.*?)^```').Groups[1].Value
foreach ($block in @($llmSpecBlock, $llmRequestBlock)) {
    foreach ($field in @('llm_call_id:', 'agent_role:', 'provider_profile_ref:', 'model:', 'session_policy:', 'context_refs:', 'prompt_payload_ref:', 'output_schema:', 'token_budget:', 'timeout_ms:')) {
        if (-not $block.Contains($field)) {
            Add-Failure "missing exact LLM call field: $field"
        }
    }
    if (-not $block.Contains('CWE_LABELING')) {
        Add-Failure 'CWE_LABELING missing from LLM call role enum'
    }
    if (-not $block.Contains('CHAINING')) {
        Add-Failure 'CHAINING missing from LLM call role enum'
    }
}
if (-not $llmRequestBlock.Contains('call_spec_ref:')) {
    Add-Failure 'LLMInvocationRequest missing call_spec_ref'
}
$llmLogBlock = [regex]::Match($contractText, '(?ms)^LLMInvocationLog:\s*(.*?)^```').Groups[1].Value
if (-not $llmLogBlock.Contains('parsed_output_ref:')) {
    Add-Failure 'LLMInvocationLog missing parsed_output_ref'
}
foreach ($pair in @(
    @{ Name = 'TechnicalEvidenceReview'; End = '## 9.' },
    @{ Name = 'RuleScopeImpactReview'; End = '```' },
    @{ Name = 'ReportDraft'; End = '```' }
)) {
    $outputPattern = '(?ms)^' + [regex]::Escape($pair.Name) + ':\s*(.*?)^' + [regex]::Escape($pair.End)
    $outputBlock = [regex]::Match($contractText, $outputPattern).Groups[1].Value
    if (-not $outputBlock.Contains('action_decision_ref:')) {
        Add-Failure "$($pair.Name) missing action_decision_ref"
    }
    if ($outputBlock.Contains('llm_invocation_log_ref:')) {
        Add-Failure "$($pair.Name) must not reverse-reference LLMInvocationLog"
    }
}

$analysisRunResultBlock = [regex]::Match($contractText, '(?ms)^AnalysisRunResult:\s*(.*?)^```').Groups[1].Value
$requiredAnalysisResultFields = @('hypothesis_duplicate_review_refs:', 'finding_refs:', 'verification_refs:', 'cwe_label_refs:', 'technical_review_refs:', 'rule_scope_review_refs:', 'policy_record_refs:', 'dynamic_request_refs:', 'dynamic_result_refs:', 'environment_recipe_refs:', 'sandbox_environment_refs:', 'agent_log_refs:', 'sandbox_policy_decision_refs:', 'cleanup_result_refs:', 'poc_candidate_refs:', 'poc_refs:', 'report_draft_refs:', 'llm_invocation_log_refs:', 'action_decision_refs:', 'work_state_refs:', 'work_attempt_refs:', 'transition_commit_refs:', 'debug_trace_ref:')
foreach ($field in $requiredAnalysisResultFields) {
    if (-not $analysisRunResultBlock.Contains($field)) {
        Add-Failure "missing AnalysisRunResult handoff field: $field"
    }
}
if ($contractText -match 'POLICY_BLOCKED[^\r\n]*정적·찬반[^\r\n]*`ACCEPT`') {
    Add-Failure 'POLICY_BLOCKED without a validated PoC must not reach Technical ACCEPT'
}
if (-not $contractText.Contains('Sandbox 실행 Agent가 호출되기 전 정책 차단도 `agent_invoked=false`와 `POLICY_BLOCKED` event를 가진 로그·결과로 확정할 수 있다.')) {
    Add-Failure 'policy block before Agent invocation must still produce an AgentLog and dynamic result'
}
$reportDraftBlock = [regex]::Match($contractText, '(?ms)^ReportDraft:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('finding_ref:', 'dynamic_result_ref:', 'poc_ref:', 'restrictions:', 'limitations:', 'unresolved_conditions:', 'redaction_status: PASSED')) {
    if (-not $reportDraftBlock.Contains($field)) {
        Add-Failure "missing ReportDraft safety field: $field"
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
    'ReportDraft 이후 Agent 자동화를 계속하려 함',
    'Agent가 사람 검토·외부 제출·공개 action을 요청',
    '선행 결과가 바뀐 오래된 ReportDraft를 current 결과로 사용',
    'restriction·limitation 또는 redaction 상태가 빠진 초안을 저장',
    '같은 ActionRequest를 동시에 두 번 검사',
    'Gate 또는 Reporter가 별도 CALL_LLM으로 우회',
    'Technical Gate `REVISE` 뒤 같은 입력으로 재투표',
    'action 허가 뒤 Gate 입력 revision이 바뀜',
    'Runtime Validator가 공식 정책 의미를 다시 판단',
    'Pro와 Con이 같은 session 또는 parent를 공유',
    '`SAVE_RESULT` 검사 뒤 candidate bytes를 바꿈',
    '실행 오류만 든 `FALSE` 후보를 저장',
    '다른 역할이 만든 결과 후보를 저장'
    '`RUN_SANDBOX` 허가 뒤 request·requirements·profile·resource/lifecycle revision이 바뀜'
    'Sandbox 내부 command가 host·Docker socket·secret·미허용 egress에 접근하려 함'
    '동적 결과의 recipe·환경·AgentLog·candidate·PoC·cleanup attempt 또는 digest가 다름'
    'Verification 또는 R7 Agent가 `DynamicReproductionResult`를 직접 저장'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$sandboxReviewPatterns = @(
    @{
        Name = 'Sandbox Controller enforces only the external isolation boundary'
        Pattern = '(?s)`action_decision_ref`는 plan 입력 부족·모순.*?pre-boundary 결과에서만 `null`.*?`action_decision_ref\.record_id`는 R7 호출자의 권한·상태·예산.*?exact `DynamicReproductionRequest`.*?current `EnvironmentRequirements`.*?Sandbox Controller는 host, Docker daemon/socket, host mount·namespace, secret, 허용되지 않은 egress, 다른 workspace와 R8 resource profile/lifecycle.*?컨테이너 내부 command를 allowlist로 재판단하지 않는다'
    },
    @{
        Name = 'ReproductionPlan is strategy rather than an execution allowlist'
        Pattern = '(?s)`ReproductionPlan`은 R7 Agent가.*?`requested_evidence`는 비어 있을 수 있는 참고 목표.*?allowlist가 아니다.*?plan에는 실행 mode, exact command·step·payload·PoC·cleanup 지시를 넣지 않는다.*?실제 수행 사실은 `AgentLog`에 남긴다'
    },
    @{
        Name = 'AgentLog is durable append-only and attempt isolated'
        Pattern = '(?s)비-LLM `Reproduction Session Manager`는.*?durable append-only `AgentLog`.*?`agent_invoked`는 외부 경계 승인 뒤 Sandbox 안에서 실행하는 R7 Agent 단계.*?`event_id`는 시스템 전체에서 고유.*?`sequence`는 attempt별 1부터 엄격히 증가.*?시작과 종료 event는 동일한 `action_id`.*?종료된 이전 attempt의 늦은 event는 current log나 결과에 붙이지 않는다'
    },
    @{
        Name = 'dynamic result save repeats same-attempt provenance checks'
        Pattern = '(?s)`SAVE_RESULT\(requested_by=REPRODUCTION_SESSION_MANAGER, result_kind=dynamic_reproduction_result\)`.*?request·purpose·plan·recipe·정책·환경·AgentLog·candidate·validated PoC·cleanup의 same-attempt 조합을 다시 확인'
    },
    @{
        Name = 'Session Manager owns logs validated PoCs and dynamic results'
        Pattern = '(?s)비-LLM Reproduction Session Manager는 append-only log, validated PoC와 `DynamicReproductionResult`의 유일한 result owner.*?Verification은.*?같은 final 결과만 읽으며 `DynamicReproductionResult`를 직접 만들거나 수정하지 않는다'
    },
    @{
        Name = 'agent invocation flag matches AgentLog lifecycle'
        Pattern = '(?s)`agent_invoked=false`인데 `AgentLog`에 `AGENT_STARTED`가 있거나, `true`인데 해당 event가 없음.*?`agent_log_ref=null`이거나 event의 `event_id`·attempt별 `sequence`·start/end `action_id` 규칙을 어김'
    },
    @{
        Name = 'cleanup NOT_REQUIRED is limited to attempts without cleanup targets'
        Pattern = '(?s)`cleanup_required`.*?`false`이면 `cleanup_status=NOT_REQUIRED`.*?`true`이면 `cleanup_status=SUCCEEDED \| FAILED`만 허용.*?실제 자원이 있는데.*?계약 위반'
    },
    @{
        Name = 'policy blocked result retains the exact Controller decision'
        Pattern = '(?s)`failure_category=POLICY_BLOCKED`이면 `action_decision_ref`와 `policy_decision_ref`가 반드시 존재.*?`decision=DENY`.*?정책의 exact revision과 사유 코드를 확인'
    },
    @{
        Name = 'pre-boundary plan failure has no sandbox or policy decision'
        Pattern = '(?s)plan 입력 부족·모순으로 RUN_SANDBOX 요청 전 종료.*?`action_decision_ref=null`.*?`policy_decision_ref=null`.*?`agent_invoked=false`.*?`BLOCKED \| FAILED \+ PLAN \+ INCONCLUSIVE`'
    },
    @{
        Name = 'invoked and successful attempts retain allow decisions'
        Pattern = '(?s)동적 재현 성공과 가설 지지.*?`policy_decision_ref\(decision=ALLOW\)`.*?`agent_invoked=true`인데 `action_decision_ref=null`, `policy_decision_ref=null` 또는 정책 decision이 `ALLOW`가 아님'
    },
    @{
        Name = 'PoC candidate and validated PoC are distinct'
        Pattern = '(?s)`poc_candidate_ref`.*?성공을 뜻하지 않는다.*?`poc_ref`는 실제 취약점 재현에 성공한 `PoCBundle`.*?`status=SUCCEEDED`.*?`hypothesis_outcome=SUPPORTED`.*?exact candidate revision과 `content_digest`를 실제 실행'
    },
    @{
        Name = 'Dynamic records have distinct R6 and R7 owners'
        Pattern = '(?s)`dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`.*?`environment_requirements -> EnvironmentRequirements -> R7_AGENT`.*?`reproduction_plan -> ReproductionPlan -> R7_AGENT`.*?`environment_recipe -> EnvironmentRecipe -> R7_SETUP_AUTOMATION`.*?`agent_log -> AgentLog -> REPRODUCTION_SESSION_MANAGER`.*?`poc_bundle -> PoCBundle -> REPRODUCTION_SESSION_MANAGER`.*?`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_SESSION_MANAGER`'
    }
)
foreach ($rule in $sandboxReviewPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #27 Sandbox review rule: $($rule.Name)"
    }
}

$environmentHandoffPatterns = @(
    @{
        Name = 'R6 owns the immutable request and R7 owns environment requirements'
        Pattern = '(?s)`DynamicReproductionRequest`는 R6 Verification이.*?불변 record.*?`EnvironmentRequirements`는 R7이 exact request.*?불변 요구사항 record'
    },
    @{
        Name = 'reproduction plan binds current exact requirements'
        Pattern = '(?s)`ReproductionPlan`은 R7 Agent가.*?`sandbox_profile_ref`는 R6 request와 exact match.*?`environment_requirements_ref`는 같은 R7 attempt의 current requirements'
    },
    @{
        Name = 'RUN_SANDBOX freezes only the external boundary inputs'
        Pattern = '(?s)`RUN_SANDBOX` action `input_refs`에는 exact request·current `EnvironmentRequirements`·`sandbox_profile_ref`·R8 resource/lifecycle profile.*?plan·candidate·command는 Sandbox 안에서 만들어질 수 있으므로 RUN_SANDBOX 선행 allowlist나 exact action input으로 요구하지 않는다'
    },
    @{
        Name = 'actual environment compares every requirement'
        Pattern = '(?s)EnvironmentCheck:.*?status: MATCH \| MISMATCH \| NOT_CHECKED \| ERROR.*?SandboxEnvironment:.*?requirements_ref: StoredDataRef.*?checks: \[EnvironmentCheck\].*?모든 `requirement_id`를 정확히 한 번씩 포함'
    },
    @{
        Name = 'environment mismatch is resolved or returned without a false verdict'
        Pattern = '(?s)필수 item에 확인된 값 차이 또는 미확인이 있으면 환경 status는 `MISMATCH`.*?setup·비교 자체의 오류가 있으면 `ERROR`.*?필수 환경 요구사항 불일치.*?자율 retry.*?외부 수정이 필요하면 `BLOCKED`.*?한도 소진이면 `FAILED`'
    },
    @{
        Name = 'environment recipe is immutable and digest bound'
        Pattern = '(?s)`EnvironmentRecipe`는 저장소와 필요한 실행 환경.*?불변 build recipe.*?별도 Dependency Scanner나 R2 사전 package prefetch를 전제로 하지 않는다.*?`base_image_digest`는 시작 image.*?`built_image_digest`는 실제 build 또는 재사용한 완성 image'
    },
    @{
        Name = 'container reuse is isolated and state aware'
        Pattern = '(?s)첫 `DYNAMIC_REPRO` attempt는.*?clean container.*?서로 다른 가설은 같은 `container_instance_id`의 writable container를 공유하지 않는다.*?`REUSED \+ NO_RELEVANT_CHANGE`.*?`STATE_CHANGED \| CONFIG_CHANGED \| STATE_UNCERTAIN`.*?runtime이 `STATE_UNCERTAIN`으로 강제'
    },
    @{
        Name = 'R7 revision cannot bypass sandbox policy'
        Pattern = '(?s)R7이 retry에서 새 requirements·plan·recipe·candidate revision을 만들더라도.*?R6 request의 목적·가설·profile을 바꾸거나 외부 경계 검사를 생략할 수 없다'
    },
    @{
        Name = 'environment secrets use opaque handles only'
        Pattern = '(?s)credential·cookie·token·password.*?저장하지 않는다.*?`secret_ref\(data_kind=secret_handle\)`'
    },
    @{
        Name = 'dynamic request and production split use a new major schema'
        Pattern = '(?s)새 plan·recipe·AgentLog·result-owner·candidate/validated PoC·retry 계약은 관련 record의 새 MAJOR schema'
    }
)
foreach ($rule in $environmentHandoffPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened R6-R7 environment handoff rule: $($rule.Name)"
    }
}

$environmentNegativeMarkers = @(
    'ReproductionPlan에 `request_ref` 또는 `environment_requirements_ref`가 없음',
    'R6가 EnvironmentRequirements를 만들거나 수정함',
    'plan과 실제 환경이 다른 requirements revision을 가리킴',
    '다른 가설의 writable container를 재사용하거나 상태 변화 뒤 그대로 사용',
    '허용 목록에 없는 version fallback을 자동 적용함',
    '오래된 EnvironmentRequirements revision을 재사용함',
    'PoC 생성·환경 구성·실행 실패를 `FALSE | HOLD`로 변환함',
    '환경 요구사항·실제 값에 credential·token 원문을 저장함',
    'R7이 request·requirements·profile·resource/lifecycle을 바꾸고 Sandbox 외부 경계 재검사를 생략함'
)
foreach ($marker in $environmentNegativeMarkers) {
    $rowPattern = '(?m)^\|\s*' + [regex]::Escape($marker) + '\s*\|'
    if ([regex]::Matches($securityText, $rowPattern).Count -ne 1) {
        Add-Failure "missing R6-R7 environment negative scenario: $marker"
    }
}

$orchestrationPath = Join-Path $repoRoot 'docs/architecture-v5/03-agent-roles-and-orchestration.md'
$orchestrationText = Get-Content -Raw -LiteralPath $orchestrationPath
$gatePath = Join-Path $repoRoot 'docs/architecture-v5/05-llm-gate-and-reporting.md'
$gateText = Get-Content -Raw -LiteralPath $gatePath
$gateWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/gate-and-reporting.md'
$gateWikiText = Get-Content -Raw -LiteralPath $gateWikiPath
$requiredAuthorityRules = @(
    '## 역할별 권한 경계',
    '## action 요청과 실행',
    'R5-01 CWE_LABELING work',
    'current CWELabel bound to that exact Verification',
    '-> Technical Evidence Gate',
    '-> Rule Scope Impact Gate',
    '`ReportDraft`는 마지막 Agent 산출물',
    'Agent 자동화 밖에서 사람이 수행한다',
    'UNUSED -> USED',
    'UNUSED -> EXPIRED',
    'requester_identity_ref',
    'valid_until',
    'work_attempt_refs',
    '한 `action_ref.record_id`에는 정확히 하나의 `decision_id`',
    'llm_call_spec_ref',
    'output은 log를 역참조하지 않는다',
    '아직 `outcome_refs`가 비어 있는 revision',
    'Technical action의 `REVISION`은 exact Verification·current CWELabel pair',
    '같은 Verification·CWELabel revision 또는 같은 domain input hash',
    '오류 층은 섞어 기록하지 않는다',
    '정책 문장이나 정책의 의미를 대신 해석하지 않는다',
    'Pro와 Con의 `SESSION` check는 독립성을 선택값이 아닌 필수 불변조건으로 검사한다',
    '`candidate_result_ref.record_id`에는 저장 runtime이 미리 발급한 결과 revision ID',
    '`VerificationResult.verdict=FALSE`이면 `falsification_results`',
    '`TransitionCommit.state=COMMITTED`가 된 뒤에만 소비할 수 있다'
)
foreach ($rule in $requiredAuthorityRules) {
    if (-not ($orchestrationText.Contains($rule) -or $gateText.Contains($rule) -or $contractText.Contains($rule) -or $resultText.Contains($rule))) {
        Add-Failure "missing R4-03 authority rule: $rule"
    }
}

$requiredR504CrossReviewRules = @(
    @{
        Name = 'Technical Gate status fixes handoff readiness'
        Text = $contractText
        Marker = '`status=ACCEPT`는 `handoff_readiness=READY`, `status=REVISE | REJECT`는 `handoff_readiness=NOT_READY`만 허용한다.'
    },
    @{
        Name = 'policy-blocked dynamic reproduction is not automatic rejection or falsification'
        Text = $contractText
        Marker = '`DynamicReproductionResult(status=BLOCKED | FAILED, failure_category=POLICY_BLOCKED)`는 가설 반증이나 Technical `REJECT`가 아니다.'
    },
    @{
        Name = 'policy freshness is explicit in the shared contract'
        Text = $contractText
        Marker = 'freshness_status: CURRENT | STALE | UNVERIFIED'
    },
    @{
        Name = 'stale or unverified policy blocks report permission'
        Text = $contractText
        Marker = '`freshness_status=STALE | UNVERIFIED`이면 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다.'
    },
    @{
        Name = 'changed upstream revisions supersede report drafts'
        Text = $contractText
        Marker = '오래된 draft는 `AnalysisRunResult.report_draft_refs`의 current 결과에 넣을 수 없다.'
    },
    @{
        Name = 'missing Finding blocks ReportDraft creation'
        Text = $contractText
        Marker = 'Finding이 없으면 `CREATE_REPORT_DRAFT`를 허용하지 않고 `AnalysisRunResult.report_draft_refs=[]`를 유지한다.'
    },
    @{
        Name = 'Wiki exposes Technical Gate handoff readiness'
        Text = $gateWikiText
        Marker = '`handoff_readiness: READY | NOT_READY`'
    }
)
foreach ($rule in $requiredR504CrossReviewRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened PR #48 cross-review rule: $($rule.Name)"
    }
}

$requiredAutomationBoundaryRules = @(
    @{
        Name = 'common contract ends Agent automation after ReportDraft and result finalization'
        Text = $contractText
        Marker = '`ReportDraft`는 마지막 Agent 산출물이고 `AnalysisRunResult` 확정은 새 판단을 생성하지 않는 저장 작업이다. 그 다음 Agent 자동화는 종료된다.'
    },
    @{
        Name = 'Gate and reporting document assigns ReportDraft safety to R5-03'
        Text = $gateText
        Marker = '`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다.'
    },
    @{
        Name = 'overview canonical flow ends automation'
        Text = $overviewText
        Marker = 'Reporter -> ReportDraft -> AnalysisRunResult -> Agent automation end'
    },
    @{
        Name = 'canonical Mermaid shows the Reporter boundary'
        Text = $diagramText
        Marker = 'REPORTER --> DRAFT[ReportDraft with restrictions limitations and redaction passed]'
    },
    @{
        Name = 'Wiki reporting summary ends automation'
        Text = $gateWikiText
        Marker = '`ReportDraft`가 마지막 Agent 산출물이며 `AnalysisRunResult` 확정 뒤 자동화가 끝납니다.'
    }
)
foreach ($rule in $requiredAutomationBoundaryRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened R5-03 automation boundary: $($rule.Name)"
    }
}

$requiredVerificationChainingContracts = @(
    'VerificationAssignment:',
    'verification_assignment_ref:',
    'ChainingResult:',
    'source_result_refs:',
    'input_primitive_refs:',
    'primitive_match_candidates:',
    'chained_hypothesis_proposals:',
    'no_match_reasons:',
    'origin: INITIAL | VERIFICATION | CHAINING',
    'source_primitive_match_id: string | null',
    'material_child_proposals:',
    'source_verification_ref:',
    'technical_review_ref:',
    'inputs: [PrimitiveDraft]',
    'result: PrimitiveDraft | null',
    'restrictions: [Restriction]',
    'PrimitiveIndexState:',
    'primitive_refs: [StoredDataRef]',
    'upstream_result_ref: StoredDataRef',
    'downstream_input_ref: StoredDataRef',
    'matched_input_id: string',
    'primitive_and_chaining_refs:'
)
foreach ($marker in $requiredVerificationChainingContracts) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing Verification/Chaining contract: $marker"
    }
}

$requiredRestrictionContractMarkers = @(
    'CodeFactRef:',
    'bundle_ref: StoredDataRef',
    'fact_id: string',
    'Restriction:',
    'restriction_id: string',
    'fact_refs: [CodeFactRef]',
    'evidence_refs: [StoredDataRef]',
    '`observed_facts[].fact_id` 집합과 `restrictions[].fact_refs[].fact_id` 집합은 서로 겹치면 안 된다.',
    '`restriction_id`와 전체 `Restriction` 객체를 그대로 보존',
    'Restriction 객체의 중복 없는 합집합',
    '| N27 | restriction 문장만 저장하거나 `fact_refs`와 `evidence_refs`를 모두 비움',
    '| N27-A | INITIAL proposal restriction의 `fact_refs`가 비어 있거나 final StaticFactBundle 밖 사실을 가리킴',
    '| N28 | 같은 `fact_id`를 proposal의 observed fact와 restriction 근거 양쪽에 넣음'
)
$hypothesisProposalBlock = [regex]::Match($contractText, '(?ms)^HypothesisProposal:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('proposal_state: HYPOTHESIS_ONLY', 'assertion_mode: NON_FINAL', 'observed_facts: [CodeFact]', 'assumptions: [string]', 'restrictions: [Restriction]', 'falsification_questions:', 'validation_checks:')) {
    if (-not $hypothesisProposalBlock.Contains($field)) {
        Add-Failure "HypothesisProposal is missing field: $field"
    }
}
foreach ($field in @('missing_information:', 'confidence:')) {
    if ($hypothesisProposalBlock.Contains($field)) {
        Add-Failure "HypothesisProposal still contains obsolete field: $field"
    }
}
foreach ($marker in $requiredRestrictionContractMarkers) {
    if (-not ($contractText.Contains($marker) -or $verificationText.Contains($marker) -or $commonWikiText.Contains($marker) -or $securityText.Contains($marker))) {
        Add-Failure "missing hypothesis restriction provenance contract: $marker"
    }
}

$requiredDuplicateLifecycleMarkers = @(
    'HypothesisDuplicateReview:',
    'candidate_hypothesis_refs: [StoredDataRef]',
    'decision: UNIQUE | DUPLICATE | UNCERTAIN',
    'duplicate_of_hypothesis_ref: StoredDataRef | null',
    'registration_reason: NOT_CHECKED | NO_CANDIDATES | UNIQUE | UNCERTAIN | CHECK_FAILED | INVALID_DUPLICATE_TARGET | DUPLICATE',
    'status: PROPOSED | SCHEMA_VALID | DUPLICATE | INVALID_OUTPUT | CANCELLED',
    '`hypothesis_duplicate_review -> HypothesisDuplicateReview -> HYPOTHESIS`',
    '같은 analysis·workspace·commit의 등록 가설만 비교 후보',
    'LLM 호출 실패·형식 오류·유효하지 않은 중복 대상은 가설을 버리는 근거가 아니다.',
    '`DUPLICATE`이면 새 `hypothesis_id`를 발급하지 않는다.',
    'final `ProposalProcessState`, 새 `VulnerabilityHypothesis`와 `HypothesisProcessState.status=REGISTERED`를 같은 atomic transition으로 확정',
    '| N29 | 중복 LLM이 runtime 후보 목록 밖 가설을 `DUPLICATE` 대상으로 지목',
    '| N30 | 중복 LLM 호출 실패·형식 오류·`UNCERTAIN`을 proposal 삭제로 처리'
)
foreach ($marker in $requiredDuplicateLifecycleMarkers) {
    if (-not ($contractText.Contains($marker) -or $orchestrationText.Contains($marker) -or $commonWikiText.Contains($marker) -or $securityText.Contains($marker))) {
        Add-Failure "missing hypothesis duplicate decision lifecycle: $marker"
    }
}

$duplicateReviewBlock = [regex]::Match($contractText, '(?ms)^HypothesisDuplicateReview:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('meta: RecordMeta without hypothesis, with attempt', 'proposal_ref:', 'candidate_hypothesis_refs:', 'decision:', 'duplicate_of_hypothesis_ref:', 'rationale:', 'llm_call_id:')) {
    if (-not $duplicateReviewBlock.Contains($field)) {
        Add-Failure "HypothesisDuplicateReview is missing field: $field"
    }
}
$proposalStateBlock = [regex]::Match($contractText, '(?ms)^ProposalProcessState:\s*(.*?)^VerificationAssignment:').Groups[1].Value
foreach ($field in @('duplicate_review_ref:', 'duplicate_of_hypothesis_ref:', 'registration_reason:')) {
    if (-not $proposalStateBlock.Contains($field)) {
        Add-Failure "ProposalProcessState is missing duplicate lifecycle field: $field"
    }
}

$activeConfidenceChecks = @(
    @{ Path = $verificationPath; Marker = 'debate 전후 verdict와 confidence 변화' },
    @{ Path = $contractPath; Marker = 'confidence range' },
    @{ Path = (Join-Path $repoRoot 'docs/governance/OPEN_QUESTIONS.md'); Marker = 'Hypothesis schema repair 횟수와 confidence 기준' },
    @{ Path = (Join-Path $repoRoot 'docs/review/ISSUE_CATALOG.md'); Marker = 'confidence는 scheduling hint' },
    @{ Path = $contractPath; Marker = 'confidence: LOW | MEDIUM | HIGH' }
)
foreach ($check in $activeConfidenceChecks) {
    $activeText = Get-Content -Raw -LiteralPath $check.Path
    if ($activeText.Contains($check.Marker)) {
        Add-Failure "obsolete active Hypothesis confidence contract remains: $($check.Marker)"
    }
}

$primitiveDraftBlock = [regex]::Match($contractText, '(?ms)^PrimitiveDraft:\s*(.*?)^VerificationMetrics:').Groups[1].Value
foreach ($field in @('draft_id:', 'entity_refs:', 'privilege_level: string | null', 'evidence_refs:', 'description:')) {
    if (-not $primitiveDraftBlock.Contains($field)) {
        Add-Failure "PrimitiveDraft is missing unified field: $field"
    }
}
foreach ($field in @('primitive_type:', 'target_asset:', 'endpoint:', 'data_type:')) {
    if ($primitiveDraftBlock.Contains($field)) {
        Add-Failure "PrimitiveDraft still contains obsolete field: $field"
    }
}

$primitiveBlock = [regex]::Match($contractText, '(?ms)^Primitive:\s*(.*?)^PrimitiveIndexState:').Groups[1].Value
foreach ($field in @('workspace_id:', 'commit_id:', 'inputs:', 'result:', 'restrictions:', 'source_hypothesis_id:', 'source_verification_ref:', 'technical_review_ref:', 'evidence_refs:', 'description:')) {
    if (-not $primitiveBlock.Contains($field)) {
        Add-Failure "Primitive is missing unified field: $field"
    }
}
foreach ($field in @('primitive_type:', 'target:', 'status:', 'rule_scope_review_ref:', 'required_preconditions:', 'eligibility:', 'superseded_by_verification_ref:', 'confidence:')) {
    if ($primitiveBlock.Contains($field)) {
        Add-Failure "Primitive still contains obsolete field: $field"
    }
}

$primitiveIndexBlock = [regex]::Match($contractText, '(?ms)^PrimitiveIndexState:\s*(.*?)^PrimitiveMatchCandidate:').Groups[1].Value
foreach ($field in @('current_verification_ref:', 'primitive_refs:', 'updated_at:')) {
    if (-not $primitiveIndexBlock.Contains($field)) {
        Add-Failure "PrimitiveIndexState is missing field: $field"
    }
}
foreach ($field in @('state_version:', 'active_required_refs:', 'active_provided_refs:')) {
    if ($primitiveIndexBlock.Contains($field)) {
        Add-Failure "PrimitiveIndexState still contains obsolete field: $field"
    }
}

$primitiveMatchBlock = [regex]::Match($contractText, '(?ms)^PrimitiveMatchCandidate:\s*(.*?)^ChainingResult:').Groups[1].Value
foreach ($field in @('upstream_result_ref:', 'downstream_input_ref:', 'matched_input_id:', 'parent_hypothesis_ids:', 'parent_verification_refs:', 'workspace_id:', 'commit_id:', 'normalized_fingerprint:', 'evidence_refs:', 'candidate_state: UNVALIDATED')) {
    if (-not $primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate is missing field: $field"
    }
}
foreach ($field in @('match_kind:', 'input_primitive_index_refs:', 'upstream_provided_ref:', 'matched_requirement_id:', 'asset_check:', 'entity_check:', 'endpoint_check:', 'privilege_check:', 'data_check:', 'attack_order_check:', 'restriction_check:', 'unresolved_conditions:')) {
    if ($primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate still contains obsolete field: $field"
    }
}

$chainingResultBlock = [regex]::Match($contractText, '(?ms)^ChainingResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('trigger:', 'input_primitive_index_refs:', 'bounded_stop_reason:')) {
    if ($chainingResultBlock.Contains($field)) {
        Add-Failure "ChainingResult still contains obsolete field: $field"
    }
}

foreach ($record in @('HeldHypothesis:', 'ConfirmedCapability:')) {
    if ($contractText.Contains($record)) {
        Add-Failure "obsolete duplicate Chaining record remains: $record"
    }
}
foreach ($field in @('root_hypothesis_id:', 'chain_depth:')) {
    if ($contractText.Contains($field)) {
        Add-Failure "obsolete derived hypothesis lineage field remains: $field"
    }
}

foreach ($forbidden in @('ResearchResult:', 'origin: INITIAL | RESEARCH | CHAINING', 'work_type: WORKSPACE_PREP | STATIC_TOOL | STATIC_NORMALIZE | HYPOTHESIS_PROPOSAL | CONTEXT_RETRIEVAL | PRO_EVIDENCE | CON_EVIDENCE | VERIFICATION | DYNAMIC_REPRO | PRIMITIVE_UPDATE | RESEARCH', 'research_requests:')) {
    if ($contractText.Contains($forbidden)) {
        Add-Failure "obsolete active Research contract remains: $forbidden"
    }
}

$verificationChainingScenarioMarkers = @(
    '| N1 | final HOLD |',
    '| N2 | final FALSE |',
    '| N3 | final TRUE, Gate 미실행 |',
    '| N4 | TRUE + Technical `ACCEPT`, Rule Scope 미실행 |',
    '| N5 | TRUE + Technical `ACCEPT` + Rule Scope `FAIL | UNCERTAIN | DENY` |',
    '| N6 | TRUE + Technical `ACCEPT` + Rule Scope `PASS/PASS/PASS/SUFFICIENT/ALLOW` |',
    '| N7 | result가 있는 TRUE Primitive + result가 없는 HOLD Primitive |',
    '| N8 | result가 있는 서로 다른 TRUE Primitive 둘 |',
    '| N9 | TRUE+TRUE 입력 중 한 부모가 Gate 전 또는 Technical 비정상 결과 |',
    '| N10 | match의 entity 또는 privilege 충족 근거가 없음 |',
    '| N10-A | 후보가 조상 경로에서 이미 사용한 Primitive를 다시 사용 |',
    '| N11 | Verification이 새 endpoint·sink·권한 경계를 발견 |',
    '| N12 | chained child가 FALSE |',
    '| N13 | Verification이 budget·Sandbox·Gate 순서를 우회하려 함 |',
    '| N13-A | 같은 역할이지만 배정되지 않은 Verification identity가 Gate·Reporter·새 verification work를 요청 |',
    '| N14 | Chaining Agent가 Primitive match 없는 bypass·impact·dynamic 요청을 출력 |',
    '| N15 | `purpose=PRODUCTION`인데 `verification_mode=BASIC | CONDITIONAL_DEBATE`를 요청 |',
    '| N16 | 운영 Pro/Con 중 하나를 실행할 예산이 부족 |',
    '| N17 | Context 조회 실패·timeout·권한 오류만으로 `HOLD`를 저장하려 함 |',
    '| N18 | 일부 Context 조회는 실패했지만 대체 조회·다른 정상 근거와 운영 Pro/Con으로 필수 검증을 완료 |',
    '| N19 | 필수 Context 또는 운영 Pro/Con을 확보하지 못했는데 final `VerificationResult`를 저장하려 함 |'
)
foreach ($marker in $verificationChainingScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing Verification/Chaining scenario: $marker"
    }
}

$requiredVerificationChainingRules = @(
    'Orchestration Agent는 한 가설 안에서 Pro/Con·동적 재현·두 Gate·Reporter·Chaining의 호출 여부나 Technical `REVISE` 목적지를 결정하지 않는다.',
    '같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달',
    'Gate 전 TRUE는 result가 있는 Primitive가 될 수 없다.',
    'origin=VERIFICATION',
    'origin=CHAINING',
    'TRUE_HOLD',
    'TRUE_TRUE',
    'upstream result가 downstream input을 충족',
    'HypothesisProcessState.status=TERMINAL',
    'VerificationAssignment.owner_identity_ref',
    'ancestor Primitive를 현재 순회의 후보에서 제외한다.',
    'Technical `ACCEPT`은 체이닝 재료의 자격을 확정하고 Rule Scope는 보고 가능성만 판단한다.',
    'Rule Scope 결과는 이미 admission된 Primitive를 취소하지 않는다.',
    'child가 FALSE여도 부모 판정은 바뀌지 않는다'
)
foreach ($rule in $requiredVerificationChainingRules) {
    if (-not ($orchestrationText.Contains($rule) -or $gateText.Contains($rule) -or $contractText.Contains($rule) -or $securityText.Contains($rule) -or $diagramText.Contains($rule))) {
        Add-Failure "missing Verification/Chaining rule: $rule"
    }
}

$requiredDebatePolicyRules = @(
    'purpose: PRODUCTION | EVALUATION',
    'PRODUCTION에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다.',
    'EVALUATION의 `BASIC | CONDITIONAL_DEBATE` 결과는 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다.',
    '예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다.'
)
foreach ($rule in $requiredDebatePolicyRules) {
    if (-not ($overviewText.Contains($rule) -or $verificationText.Contains($rule) -or $contractText.Contains($rule) -or $securityText.Contains($rule))) {
        Add-Failure "missing production debate rule: $rule"
    }
}

$obsoleteDebatePolicyPhrases = @(
    '기본 검증 모드는 `CONDITIONAL_DEBATE`다.',
    '| `CONDITIONAL_DEBATE` | trigger 충족 시 Pro/Con을 독립 병렬 호출 | 기본값 |',
    '예산이 부족할 때는 생략 사유를 기록하고 BASIC으로 종료할 수 있다.'
)
foreach ($phrase in $obsoleteDebatePolicyPhrases) {
    if ($activeDebateText.Contains($phrase)) {
        Add-Failure "obsolete production debate rule remains: $phrase"
    }
}

$requiredContextFailureRules = @(
    @{
        Name = 'Context errors and affected gaps are both recorded'
        Text = $contractText
        Marker = '실패 사건은 `AnalysisError(stage=CONTEXT)`로, 그 때문에 확인하지 못한 코드 범위는 `DataGap(stage=CONTEXT)`으로 각각 기록한다.'
    },
    @{
        Name = 'Context errors and gaps are not verdict evidence'
        Text = $resultText
        Marker = '`AnalysisError`와 `DataGap` 자체는 supporting evidence, counter evidence 또는 falsification evidence가 아니다.'
    },
    @{
        Name = 'Partial Context failure may still allow a final verdict after required validation'
        Text = $contractText
        Marker = '일부 요청이 실패했어도 제한 retry·대체 조회 또는 다른 정상 근거로 가설의 모든 `validation_checks`, 모든 반증 질문과 운영 Pro/Con을 완료했다면 Verification은 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있다.'
    },
    @{
        Name = 'Missing required Context or production debate blocks the final VerificationResult'
        Text = $contractText
        Marker = '필수 Context나 운영 Pro/Con을 확보하지 못해 검증 절차 자체를 완료하지 못했다면 final `VerificationResult`를 만들지 않는다.'
    },
    @{
        Name = 'Retryable and exhausted Context failures map to BLOCKED and FAILED'
        Text = $contractText
        Marker = '재시도할 수 있으면 해당 Verification work를 `BLOCKED`로 두고 `HypothesisProcessState.status=VERIFYING`을 유지한다. 허용된 재시도를 소진했거나 복구할 수 없으면 같은 atomic transition에서 work와 가설 처리 상태를 `FAILED`로 남긴다.'
    },
    @{
        Name = 'Simple Wiki explains that a Context error alone is not HOLD'
        Text = $commonWikiText
        Marker = '단순 조회 오류만으로 `HOLD`를 만들지 않습니다.'
    },
    @{
        Name = 'Canonical Context diagram has the no-final-verdict failure branch'
        Text = $diagramText
        Marker = 'FAIL[Atomic work FAILED plus hypothesis FAILED no final result]'
    }
)
foreach ($rule in $requiredContextFailureRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened Context failure contract: $($rule.Name)"
    }
}

$requiredVerificationCompletionRules = @(
    'ValidationCheck:',
    'validation_id: string',
    'instruction: string',
    'ValidationCheckResult:',
    'completion: COMPLETE | INCOMPLETE',
    'validation_checks: [ValidationCheck]',
    'validation_results: [ValidationCheckResult]'
)
foreach ($marker in $requiredVerificationCompletionRules) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing enforceable validation completion contract: $marker"
    }
}

$requiredVerificationCompletionSemantics = @(
    '가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal',
    '모든 `ValidationCheckResult.completion=COMPLETE`',
    '각 결과의 `evidence_refs`가 하나 이상',
    '`INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다.'
)
foreach ($marker in $requiredVerificationCompletionSemantics) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing structural validation completion rule: $marker"
    }
}

$requiredHypothesisFailureRules = @(
    'status: REGISTERED | ASSIGNED | VERIFYING | TERMINAL | FAILED | CANCELLED',
    '`HypothesisProcessState.status=FAILED`',
    '`verification_result_ref=null`',
    '같은 `VERIFICATION` work의 `FAILED` revision',
    '`VERIFICATION`의 `FAILED`와 `HypothesisProcessState.status=FAILED`',
    '`failed_hypothesis_count`'
)
foreach ($marker in $requiredHypothesisFailureRules) {
    if (-not ($contractText.Contains($marker) -or $resultText.Contains($marker) -or $orchestrationText.Contains($marker) -or $commonWikiText.Contains($marker))) {
        Add-Failure "missing no-verdict hypothesis failure contract: $marker"
    }
}

$requiredTechnicalGateScopeRules = @(
    'final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다.',
    '`FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.'
)
foreach ($marker in $requiredTechnicalGateScopeRules) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing exact Technical Gate TRUE-only scope rule: $marker"
    }
}

$requiredValidatedPocContractMarkers = @(
    'DynamicReproductionRequest:',
    'purpose: POC_CONFIRMATION | VERDICT_EVIDENCE',
    'dynamic_request_ref: StoredDataRef | null',
    'request_ref: StoredDataRef',
    'poc_candidate_ref: StoredDataRef | null',
    '`dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`',
    '`environment_requirements -> EnvironmentRequirements -> R7_AGENT`',
    '`reproduction_plan -> ReproductionPlan -> R7_AGENT`',
    '`environment_recipe -> EnvironmentRecipe -> R7_SETUP_AUTOMATION`',
    '`agent_log -> AgentLog -> REPRODUCTION_SESSION_MANAGER`',
    '`poc_bundle -> PoCBundle -> REPRODUCTION_SESSION_MANAGER`',
    '`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_SESSION_MANAGER`',
    'final `TRUE`에는 current Verification generation의 exact `DynamicReproductionRequest`',
    '`SUCCEEDED + SUPPORTED`',
    'validated `poc_ref`',
    '한 Verification generation에는 `DYNAMIC_REPRO` work를 최대 하나만',
    'PoC 생성·실행 실패를 `FALSE | HOLD`로 변환하지 않는다'
)
foreach ($marker in $requiredValidatedPocContractMarkers) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing validated PoC contract marker: $marker"
    }
}

$requiredValidatedPocCrossDocumentMarkers = @(
    @{
        Name = 'R6 sends purpose-bound dynamic request and R7 owns production'
        Text = $verificationText
        Marker = 'R6는 목적과 필요한 조건만 정하며 `EnvironmentRequirements`, `ReproductionPlan`, recipe, command 또는 PoC를 생산하지 않는다.'
    },
    @{
        Name = 'overview blocks TRUE without validated PoC'
        Text = $overviewText
        Marker = 'validated PoC가 없는 `TRUE`는 저장하거나 Technical Gate로 전달하지 않는다.'
    },
    @{
        Name = 'canonical diagram shows the validated PoC gate'
        Text = $diagramText
        Marker = 'POCOK{Validated PoC and supported result}'
    },
    @{
        Name = 'security negative scenario rejects PoC-less TRUE'
        Text = $securityText
        Marker = 'validated PoC 없이 `TRUE` 저장 또는 Technical Gate 호출'
    }
)
foreach ($rule in $requiredValidatedPocCrossDocumentMarkers) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing validated PoC cross-document rule: $($rule.Name)"
    }
}

$obsoleteContextFailurePhrases = @(
    '잘림·조회 실패를 숨기지 않고 HOLD 또는 추가 조회 판단에 전달',
    'Verification Agent가 다른 근거와 함께 `HOLD` 여부 결정',
    'required_validation:',
    '근거가 verdict를 의미상 충분히 지지하는지는 Technical Evidence Gate가 검토한다.'
)
foreach ($phrase in $obsoleteContextFailurePhrases) {
    if ($activeDebateText.Contains($phrase)) {
        Add-Failure "obsolete Context failure contract remains: $phrase"
    }
}

$ruleExecutionItemBlock = [regex]::Match($contractText, '(?ms)^RuleExecutionItem:\s*(.*?)^RuleExecutionRecord:').Groups[1].Value
$requiredRuleExecutionItemFields = @(
    'rule_id: string',
    'selection_status: SELECTED | NOT_SELECTED',
    'execution_status: EXECUTED | NOT_EXECUTED | UNKNOWN',
    'hit_count: integer | null',
    'reason: NOT_SELECTED | TOOL_FAILURE | UNSUPPORTED | CANCELLED | TELEMETRY_MISSING | OTHER | null',
    'detail: string | null'
)
foreach ($field in $requiredRuleExecutionItemFields) {
    if (-not $ruleExecutionItemBlock.Contains($field)) {
        Add-Failure "RuleExecutionItem is missing field: $field"
    }
}

$toolSourceBlock = [regex]::Match($contractText, '(?ms)^ToolSource:\s*(.*?)^CodeFact:').Groups[1].Value
if (-not $toolSourceBlock.Contains('attempt_id: string')) {
    Add-Failure 'ToolSource is missing attempt_id'
}

$ruleExecutionRecordBlock = [regex]::Match($contractText, '(?ms)^RuleExecutionRecord:\s*(.*?)^ToolRunResult:').Groups[1].Value
$requiredRuleExecutionRecordFields = @(
    'meta: RecordMeta without hypothesis, with attempt',
    'tool_name: string',
    'tool_version: string',
    'analysis_config_ref: StoredDataRef',
    'rule_catalog_ref: StoredDataRef',
    'selected_rule_packs: [string]',
    'rules: [RuleExecutionItem]'
)
foreach ($field in $requiredRuleExecutionRecordFields) {
    if (-not $ruleExecutionRecordBlock.Contains($field)) {
        Add-Failure "RuleExecutionRecord is missing field: $field"
    }
}

$toolRunResultBlock = [regex]::Match($contractText, '(?ms)^ToolRunResult:\s*(.*?)^ContextRetrievalLimits:').Groups[1].Value
foreach ($field in @('tool_kind: STRUCTURE | RULE_BASED', 'rule_execution_ref: StoredDataRef | null')) {
    if (-not $toolRunResultBlock.Contains($field)) {
        Add-Failure "ToolRunResult is missing field: $field"
    }
}

$requiredRuleExecutionSemantics = @(
    @{ Name = 'zero hit is an executed rule'; Text = $contractText; Marker = '`hit_count=0`만이 “규칙을 실행했지만 탐지 결과가 0건”이라는 뜻이다.' },
    @{ Name = 'not executed and unknown never use zero'; Text = $contractText; Marker = '`NOT_EXECUTED | UNKNOWN`에서 `hit_count=0`을 쓰는 것도 금지한다.' },
    @{ Name = 'other reason requires detail'; Text = $contractText; Marker = '`reason=OTHER`이면 사람이 이해할 수 있는 비어 있지 않은 `detail`이 필수다.' },
    @{ Name = 'CodeFact is bound to a tool attempt'; Text = $contractText; Marker = '`CodeFact.producer.attempt_id`는 이 사실을 만든 exact `ToolRunResult.attempt_id`와 같아야 한다.' },
    @{ Name = 'missing CodeFact does not prove zero'; Text = $staticText; Marker = '`CodeFact`가 없다는 사실만으로 규칙을 실행했거나 결과가 0건이었다고 추정하지 않는다.' },
    @{ Name = 'retry keeps rule records separate'; Text = $contractText; Marker = '이전 attempt의 규칙 상태나 탐지 수를 합치지 않는다.' },
    @{ Name = 'R8 separates plan and execution coverage'; Text = $resultText; Marker = '실행 coverage는 `SELECTED` 규칙 중 `EXECUTED` 비율, 계획 coverage는 catalog 규칙 중 `SELECTED` 비율로 따로 계산' },
    @{ Name = 'security blocks zero-hit inference'; Text = $securityText; Marker = '`CodeFact`가 없다는 이유만으로 규칙 실행 0건을 기록' },
    @{ Name = 'Wiki explains the three execution meanings'; Text = $commonWikiText; Marker = '`EXECUTED + hit_count=0`: 검사했지만 탐지 결과가 0건입니다.' },
    @{ Name = 'result owner registry protects rule records'; Text = $contractText; Marker = '`rule_execution_record -> RuleExecutionRecord -> STATIC_ANALYSIS`' }
)
foreach ($rule in $requiredRuleExecutionSemantics) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened rule execution contract: $($rule.Name)"
    }
}

$obsoleteRuleExecutionPhrases = @(
    '어떤 rule/rule pack을 실제로 실행했는지 추적할 방법이 아직 없다.',
    '이 계약은 이 PR에서 확정하지 않으므로 후속 **Issue #82**로 분리'
)
foreach ($phrase in $obsoleteRuleExecutionPhrases) {
    if ($staticText.Contains($phrase)) {
        Add-Failure "obsolete unresolved rule execution statement remains: $phrase"
    }
}

$ruleExecutionDecisionPath = Join-Path $repoRoot 'docs/review/decisions/ADR-006-static-rule-execution-record.md'
if (-not (Test-Path -LiteralPath $ruleExecutionDecisionPath)) {
    Add-Failure 'missing ADR-006 static rule execution decision'
} else {
    $ruleExecutionDecisionText = Get-Content -Raw -LiteralPath $ruleExecutionDecisionPath
    foreach ($marker in @('상태: `ACCEPTED`', 'RunMeta', 'RuleExecutionRecord', 'ToolRunResult.tool_kind', 'ToolSource.attempt_id', '새 MAJOR schema', 'R2:', 'R4:', 'R8:')) {
        if (-not $ruleExecutionDecisionText.Contains($marker)) {
            Add-Failure "ADR-006 is missing decision marker: $marker"
        }
    }
}
$decisionIndexText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/review/decisions/README.md')
if (-not $decisionIndexText.Contains('[ADR-006](./ADR-006-static-rule-execution-record.md)')) {
    Add-Failure 'decision index is missing ADR-006'
}

$staticFactBundleBlock = [regex]::Match($contractText, '(?ms)^StaticFactBundle:\s*(.*?)^```').Groups[1].Value
$requiredStaticFactBundleFields = @(
    'source_candidates: [CodeFact]',
    'sink_candidates: [CodeFact]',
    'sanitizer_candidates: [CodeFact]',
    'validator_candidates: [CodeFact]',
    'auth_and_permission_checks: [CodeFact]',
    'other_facts: [CodeFact]'
)
foreach ($field in $requiredStaticFactBundleFields) {
    if (-not $staticFactBundleBlock.Contains($field)) {
        Add-Failure "StaticFactBundle is missing fact-kind list: $field"
    }
}

$requiredStaticFactBundleSemantics = @(
    @{ Name = 'closed fact-kind mapping'; Marker = '`source_candidates -> SOURCE`, `sink_candidates -> SINK`, `sanitizer_candidates -> SANITIZER`, `validator_candidates -> VALIDATOR`, `auth_and_permission_checks -> AUTH_CHECK | PERMISSION_CHECK`, `other_facts -> OTHER`' },
    @{ Name = 'global fact id uniqueness'; Marker = '여섯 목록의 합집합에서 `fact_id`는 정확히 한 번만 나타나야 한다.' },
    @{ Name = 'empty candidate list is not safety proof'; Marker = '빈 배열은 후보가 없다는 현재 관찰일 뿐, 안전함이나 검증 완료를 증명하지 않는다.' },
    @{ Name = 'one location can have multiple fact roles'; Marker = '같은 코드 위치가 둘 이상의 역할을 가지면 역할마다 별도 `CodeFact`와 서로 다른 `fact_id`를 만든다.' },
    @{ Name = 'defense candidates are not verdicts'; Marker = '`SANITIZER`와 `VALIDATOR`는 방어 로직 후보이며 안전함, 경로 차단 또는 `FALSE`의 자동 근거가 아니다.' },
    @{ Name = 'exact bundle identity and tool provenance'; Marker = '모든 `CodeFact`는 bundle의 `analysis_id` 범위에만 속하고 `location.workspace_id | commit_id`가 bundle과 같아야 한다. `producer.attempt_id`는 current `ToolRunResult`를, 규칙 기반 사실의 `producer.rule_id`는 같은 attempt의 `RuleExecutionRecord.rules[]` 항목을 가리켜야 한다.' },
    @{ Name = 'normalizer uses the static analysis identity'; Marker = '`Static Fact Normalizer`는 result-owner registry의 `STATIC_ANALYSIS` 신뢰 identity로 실행되는 정규화 component이며 별도 권한 역할이 아니다.' },
    @{ Name = 'static bundle result owner'; Marker = '`static_fact_bundle -> StaticFactBundle -> STATIC_ANALYSIS`' },
    @{ Name = 'static bundle save validation'; Marker = '`result_kind=static_fact_bundle`' },
    @{ Name = 'static bundle major schema migration'; Marker = 'StaticFactBundle 새 MAJOR schema' }
)
foreach ($rule in $requiredStaticFactBundleSemantics) {
    if (-not $contractText.Contains($rule.Marker)) {
        Add-Failure "missing StaticFactBundle contract rule: $($rule.Name)"
    }
}

$glossaryText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/GLOSSARY.md')
$reviewChecklistText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/governance/REVIEW_CHECKLIST.md')
$issueCatalogText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/review/ISSUE_CATALOG.md')
$requiredStaticFactBundleCrossDocumentRules = @(
    @{ Name = 'static layer declares sanitizer list'; Text = $staticText; Marker = 'sanitizer_candidates: []' },
    @{ Name = 'static layer declares validator list'; Text = $staticText; Marker = 'validator_candidates: []' },
    @{ Name = 'static layer declares other facts list'; Text = $staticText; Marker = 'other_facts: []' },
    @{ Name = 'results document measures fact kinds'; Text = $resultText; Marker = '`fact_kind`별 후보 수' },
    @{ Name = 'security rejects mismatched fact lists'; Text = $securityText; Marker = '`fact_kind`와 다른 후보 목록에 저장하거나 여섯 목록에서 같은 `fact_id`를 중복 사용' },
    @{ Name = 'security rejects defense candidate as a verdict'; Text = $securityText; Marker = '`SANITIZER | VALIDATOR` 후보만으로 안전함·경로 차단·`FALSE`를 확정' },
    @{ Name = 'Wiki explains defense candidates'; Text = $commonWikiText; Marker = '`sanitizer_candidates`와 `validator_candidates`는 방어 로직의 **후보**' },
    @{ Name = 'glossary explains sanitizer candidate'; Text = $glossaryText; Marker = '**Sanitizer candidate**' },
    @{ Name = 'glossary explains validator candidate'; Text = $glossaryText; Marker = '**Validator candidate**' },
    @{ Name = 'governance checks kind partition'; Text = $reviewChecklistText; Marker = '`StaticFactBundle`의 여섯 `CodeFact` 목록' },
    @{ Name = 'R2 issue catalog owns the mapping'; Text = $issueCatalogText; Marker = '`source_candidates | sink_candidates | sanitizer_candidates | validator_candidates | auth_and_permission_checks | other_facts`' }
)
foreach ($rule in $requiredStaticFactBundleCrossDocumentRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing StaticFactBundle cross-document rule: $($rule.Name)"
    }
}

$staticFactDecisionPath = Join-Path $repoRoot 'docs/review/decisions/ADR-010-static-fact-kind-partition.md'
if (-not (Test-Path -LiteralPath $staticFactDecisionPath)) {
    Add-Failure 'missing ADR-010 StaticFactBundle fact-kind partition decision'
} else {
    $staticFactDecisionText = Get-Content -Raw -LiteralPath $staticFactDecisionPath
    foreach ($marker in @('상태: `ACCEPTED`', 'sanitizer_candidates', 'validator_candidates', 'other_facts', '새 MAJOR schema', 'R2:', 'R4:', 'R6:')) {
        if (-not $staticFactDecisionText.Contains($marker)) {
            Add-Failure "ADR-010 is missing decision marker: $marker"
        }
    }
}
$cweLabelDecisionPath = Join-Path $repoRoot 'docs/review/decisions/ADR-009-r5-01-cwe-labeling-provenance.md'
if (-not (Test-Path -LiteralPath $cweLabelDecisionPath)) {
    Add-Failure 'missing ADR-009 R5-01 CWE labeling provenance decision'
} else {
    $cweLabelDecisionText = Get-Content -Raw -LiteralPath $cweLabelDecisionPath
    foreach ($marker in @('상태: `ACCEPTED`', 'R5-01', 'CWE_LABELING', 'verification_result_ref', 'verification_generation', 'cwe_labeling_work_id', 'llm_call_id', 'Technical Gate')) {
        if (-not $cweLabelDecisionText.Contains($marker)) {
            Add-Failure "ADR-009 is missing decision marker: $marker"
        }
    }
}
if (-not $decisionIndexText.Contains('[ADR-009](./ADR-009-r5-01-cwe-labeling-provenance.md)')) {
    Add-Failure 'decision index is missing ADR-009'
}
if (-not $decisionIndexText.Contains('[ADR-010](./ADR-010-static-fact-kind-partition.md)')) {
    Add-Failure 'decision index is missing ADR-010'
}

$requiredCweLabelCrossDocumentRules = @(
    @{
        Name = 'overview fixes R5-01 between final TRUE and Technical Gate'
        Text = $overviewText
        Marker = 'R5-01 `CWE_LABELING`이 exact Verification에 맞는 current `CWELabel` 생성'
    },
    @{
        Name = 'gate reviews an exact Verification and current CWELabel pair'
        Text = $gateText
        Marker = 'Technical Gate는 current label의 정합성만 검토하고 이를 생성·수정·덮어쓰지 않는다.'
    },
    @{
        Name = 'security rejects stale labels on a new Verification'
        Text = $securityText
        Marker = '새 Verification에 같은 CWE 값의 과거 `CWELabel`을 재사용'
    },
    @{
        Name = 'security rejects Gate ownership of CWE labels'
        Text = $securityText
        Marker = 'Technical Gate가 `CWELabel`을 생성·수정하거나 새 CWE를 저장하려 함'
    },
    @{
        Name = 'canonical diagram names the R5-01 CWE stage'
        Text = $diagramText
        Marker = 'R5-01 CWE_LABELING creates current CWELabel bound to exact Verification'
    },
    @{
        Name = 'Wiki quick guide names the exact R5-01 CWE stage'
        Text = (Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/quick-guide.md'))
        Marker = 'R5-01 CWE_LABELING이 exact Verification에 맞는 current CWELabel 생성'
    }
)
foreach ($rule in $requiredCweLabelCrossDocumentRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing R5-01 CWE labeling cross-document rule: $($rule.Name)"
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
Write-Output "R4 Pro/Con result fields: $($requiredEvidenceAgentResultFields.Count)"
Write-Output "R4 Verification join fields: $($requiredVerificationDebateFields.Count)"
Write-Output "R5-01 CWELabel fields: $($requiredCweLabelFields.Count)"
Write-Output "R5-01 CWELabel contract rules: $($requiredCweLabelContractMarkers.Count)"
Write-Output "R4 Pro/Con join rules: $($requiredDebateContractMarkers.Count)"
Write-Output "R4-02 TransitionCommit atomic fields: $($requiredTransitionCommitFields.Count)"
Write-Output "R4-02 exact output bindings: $($requiredBindingRules.Count)"
Write-Output "R4-02 review remediation rules: $($reviewRemediationPatterns.Count)"
Write-Output "R4-02 required error codes: $($requiredErrorCodes.Count)"
Write-Output "R4-02 negative scenarios: $($negativeScenarioMarkers.Count)"
Write-Output "R4-03 required contract names: $($requiredR403ContractNames.Count)"
Write-Output "R4-03 action types: $($requiredActionTypes.Count)"
Write-Output "R4-03 exact action check bindings: $($requiredActionCheckBindings.Count)"
Write-Output "R4-03 exact requester bindings: $($requiredActionRequesterBindings.Count)"
Write-Output "R4-03 ActionCheck types: $($requiredActionChecks.Count)"
Write-Output "R4-03 AnalysisRunResult handoff fields: $($requiredAnalysisResultFields.Count)"
Write-Output 'R5-03 ReportDraft safety fields: 7'
Write-Output 'R4-03 exact LLM call blocks: 2'
Write-Output "R4-03 authority errors: $($requiredAuthorityErrors.Count)"
Write-Output "R4-03 authority scenarios: $($authorityScenarioMarkers.Count)"
Write-Output "R4-03 authority rules: $($requiredAuthorityRules.Count)"
Write-Output "R5-01 CWELabel cross-document rules: $($requiredCweLabelCrossDocumentRules.Count)"
Write-Output "R5-03 automation boundary rules: $($requiredAutomationBoundaryRules.Count)"
Write-Output "R4-03 Sandbox review rules: $($sandboxReviewPatterns.Count)"
Write-Output "R6-R7 environment handoff rules: $($environmentHandoffPatterns.Count)"
Write-Output "R6-R7 environment negative scenarios: $($environmentNegativeMarkers.Count)"
Write-Output "Verification/Chaining contract markers: $($requiredVerificationChainingContracts.Count)"
Write-Output "Hypothesis restriction provenance markers: $($requiredRestrictionContractMarkers.Count)"
Write-Output "Hypothesis duplicate lifecycle markers: $($requiredDuplicateLifecycleMarkers.Count)"
Write-Output 'HypothesisProposal required fields: 7'
Write-Output 'HypothesisDuplicateReview required fields: 7'
Write-Output 'ProposalProcessState duplicate fields: 3'
Write-Output "Verification/Chaining scenarios: $($verificationChainingScenarioMarkers.Count)"
Write-Output "Verification/Chaining semantic rules: $($requiredVerificationChainingRules.Count)"
Write-Output "Production debate policy rules: $($requiredDebatePolicyRules.Count)"
Write-Output "Context failure contract rules: $($requiredContextFailureRules.Count)"
Write-Output "Validation completion contract rules: $($requiredVerificationCompletionRules.Count)"
Write-Output "Validation completion semantic rules: $($requiredVerificationCompletionSemantics.Count)"
Write-Output "No-verdict hypothesis failure rules: $($requiredHypothesisFailureRules.Count)"
Write-Output "Technical Gate TRUE-only scope rules: $($requiredTechnicalGateScopeRules.Count)"
Write-Output "Validated PoC contract markers: $($requiredValidatedPocContractMarkers.Count)"
Write-Output "Validated PoC cross-document rules: $($requiredValidatedPocCrossDocumentMarkers.Count)"
Write-Output "Obsolete Context failure phrases: $($obsoleteContextFailurePhrases.Count)"
Write-Output "Rule execution item fields: $($requiredRuleExecutionItemFields.Count)"
Write-Output "Rule execution record fields: $($requiredRuleExecutionRecordFields.Count)"
Write-Output "Rule execution semantic rules: $($requiredRuleExecutionSemantics.Count)"
Write-Output "Obsolete rule execution phrases: $($obsoleteRuleExecutionPhrases.Count)"
Write-Output "StaticFactBundle fact-kind fields: $($requiredStaticFactBundleFields.Count)"
Write-Output "StaticFactBundle semantic rules: $($requiredStaticFactBundleSemantics.Count)"
Write-Output "StaticFactBundle cross-document rules: $($requiredStaticFactBundleCrossDocumentRules.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
