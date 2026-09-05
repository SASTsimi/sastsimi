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
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
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
$diagramText = Get-Content -Raw -Encoding UTF8 -LiteralPath $diagramPath
$wikiDiagramText = Get-Content -Raw -Encoding UTF8 -LiteralPath $wikiDiagramPath
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
$requiredDynamicStateDiagramMarkers = @(
    'RUNNING --> RUNNING: same session command PoC environment adjustment',
    'RUNNING --> READY: session restart trigger RETRY',
    'BLOCKED --> READY: external condition resolved trigger RESUME'
)
foreach ($marker in $requiredDynamicStateDiagramMarkers) {
    if (-not $diagramText.Contains($marker)) {
        Add-Failure "canonical state diagram is missing dynamic lifecycle marker: $marker"
    }
}

# R5-03 Finding lifecycle: with a Rule Scope review present (FOUND or ABSENT_CONFIRMED)
# the RuleScopeImpactReview is COMMITTED, so every Reporter-blocking Gate outcome
# (UNCERTAIN, DENY, ...) must still pass through FINDING_NORMALIZE before Reporter
# BLOCK. Any Mermaid block that models both ABSENT_CONFIRMED and FINDING_NORMALIZE
# must not contain a direct edge from a Rule Scope branch node to the report-block
# node. The COLLECTION_FAILED path (no RuleScopeImpactReview, no Finding) stays
# allowed: its edge originates from the policy-collection node, not a Rule Scope
# branch node.
foreach ($diagramSource in @(
    @{ Label = 'canonical'; Blocks = $diagramBlocks },
    @{ Label = 'Wiki'; Blocks = $wikiDiagramBlocks }
)) {
    foreach ($block in $diagramSource.Blocks) {
        if (($block -notmatch 'FINDING_NORMALIZE') -or ($block -notmatch 'ABSENT_CONFIRMED')) {
            continue
        }
        $normMatch = [regex]::Match($block, '(\w+)\[FINDING_NORMALIZE')
        $blockNodeMatch = [regex]::Match($block, '(\w+)\[Report blocked\]')
        if (-not ($normMatch.Success -and $blockNodeMatch.Success)) {
            Add-Failure "$($diagramSource.Label) Mermaid Finding lifecycle block is missing a FINDING_NORMALIZE or 'Report blocked' node"
            continue
        }
        $normNode = $normMatch.Groups[1].Value
        $blockNode = $blockNodeMatch.Groups[1].Value

        # Rule Scope branch nodes: the target of the FOUND edge and the target of
        # the ABSENT_CONFIRMED edge out of the policy-collection node.
        $branchNodes = [regex]::Matches($block, '[-.=]+>\s*\|[^|]*(?:FOUND|ABSENT_CONFIRMED)[^|]*\|\s*(\w+)') |
            ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        if ($branchNodes.Count -eq 0) {
            Add-Failure "$($diagramSource.Label) Mermaid Finding lifecycle block has no identifiable Rule Scope branch node"
        }
        foreach ($branchNode in $branchNodes) {
            # An edge line from $branchNode to a target node id, allowing any
            # connector style (-->, -.->, ==>) and an optional edge label, and
            # tolerating an optional `[label]` shape declaration on the target.
            $edge = '(?m)^\s*' + [regex]::Escape($branchNode) + '\s*[-.=]+>\s*(?:\|[^|]*\|\s*)?'
            if ([regex]::IsMatch($block, ($edge + [regex]::Escape($blockNode) + '\b'))) {
                Add-Failure "$($diagramSource.Label) Mermaid has a forbidden direct '$branchNode -> $blockNode' edge that bypasses FINDING_NORMALIZE on a Rule Scope review path"
            }
            if (-not [regex]::IsMatch($block, ($edge + [regex]::Escape($normNode) + '\b'))) {
                Add-Failure "$($diagramSource.Label) Mermaid Rule Scope branch '$branchNode' no longer routes through FINDING_NORMALIZE ('$branchNode -> $normNode' edge missing)"
            }
        }
    }
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
    'human_reviews',
    '가설의 `vulnerability_type`'
)
foreach ($path in $activeContractPaths) {
    $files = Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.md'
    foreach ($file in $files) {
        $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
        foreach ($pattern in $forbiddenPatterns) {
            if ($text.Contains($pattern)) {
                Add-Failure "forbidden obsolete active contract '$pattern': $($file.FullName)"
            }
        }
    }
}
foreach ($filePath in @((Join-Path $repoRoot 'README.md'), (Join-Path $repoRoot 'docs/GLOSSARY.md'))) {
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $filePath
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
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
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
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
    foreach ($pattern in $obsoleteR7SchemaPatterns) {
        if ($text.Contains($pattern)) {
            Add-Failure "obsolete pre-ADR-007 R7 schema term '$pattern': $($file.FullName)"
        }
    }
}

$contractPath = Join-Path $repoRoot 'docs/architecture-v5/08-lightweight-data-contracts.md'
$contractText = Get-Content -Raw -Encoding UTF8 -LiteralPath $contractPath
$overviewPath = Join-Path $repoRoot 'docs/architecture-v5/01-system-overview.md'
$overviewText = Get-Content -Raw -Encoding UTF8 -LiteralPath $overviewPath
$verificationPath = Join-Path $repoRoot 'docs/architecture-v5/04-verification-and-dynamic-reproduction.md'
$verificationText = Get-Content -Raw -Encoding UTF8 -LiteralPath $verificationPath
$activeDebateFiles = @(
    (Get-Item -LiteralPath (Join-Path $repoRoot 'README.md'))
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5') -Recurse -File -Filter '*.md'
) + @(
    Get-ChildItem -LiteralPath (Join-Path $repoRoot 'docs/governance') -Recurse -File -Filter '*.md'
)
$activeDebateText = ($activeDebateFiles | ForEach-Object { Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName }) -join "`n"
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
        Pattern = '(?s)R7이 스스로 해결할 수 있는 command·PoC·환경 조정은 `BLOCKED` 사유가 아니며.*?같은 session의 현재 attempt.*?`RUNNING -> READY -> RUNNING`.*?`trigger=RETRY`.*?외부 조건이 해결되면 같은 `work_id`에서 새 `attempt_id`, `trigger=RESUME`'
    },
    @{
        Name = 'dynamic cancellation result is atomically bound and late output is stale'
        Pattern = '(?s)`DYNAMIC_REPRO` 취소 전이.*?`DynamicReproductionResult\(status=CANCELLED\)`.*?같은 atomic transition.*?이미 `CANCELLED`가 확정된 뒤 늦게 도착한 output.*?연결하지 않는다'
    },
    @{
        Name = 'exact Technical and Rule Scope domain input sets'
        Pattern = '(?s)Gate domain input set.*?`TECHNICAL_GATE`에서는 `VerificationResult`와 `CWELabel` reference가 정확한 domain input set.*?`RULE_SCOPE_GATE`에서는 `VerificationResult`, `TechnicalEvidenceReview`, `CWELabel`, 정확히 하나의 `PolicyCollectionResult`.*?`FOUND`일 때만 exact `ProgramPolicyRecord` reference가 domain input set'
    },
    @{
        Name = 'Gate result references match the frozen work inputs'
        Pattern = '(?s)`TechnicalEvidenceReview` 안의 `verification_result_ref`와 `cwe_label_ref`.*?Technical Gate work의 domain input 두 개와 각각 exact match.*?`RuleScopeImpactReview` 안의 `verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_collection_result_ref`, `policy_record_ref`.*?Rule Scope Gate work의 domain input set과 exact match'
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
$resultText = Get-Content -Raw -Encoding UTF8 -LiteralPath $resultPath
$staticPath = Join-Path $repoRoot 'docs/architecture-v5/02-static-fact-layer.md'
$staticText = Get-Content -Raw -Encoding UTF8 -LiteralPath $staticPath
$commonWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/common-contracts.md'
$commonWikiText = Get-Content -Raw -Encoding UTF8 -LiteralPath $commonWikiPath
$authorityWikiText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/authority-boundaries.md')
$chainingWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/chaining.md'
$chainingWikiText = Get-Content -Raw -Encoding UTF8 -LiteralPath $chainingWikiPath
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
$securityText = Get-Content -Raw -Encoding UTF8 -LiteralPath $securityPath
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
    'SandboxProfile:',
    'DynamicReproductionLifecycleProfile:',
    'EnvironmentRecipe:',
    'SandboxEnvironment:',
    'PlanIssueItem:',
    'SandboxPolicyDecision:',
    'SandboxCommandRecord:',
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
    'sandbox_profile_ref:',
    'resource_profile_ref:'
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
$reproductionPlanBlock = [regex]::Match($contractText, '(?ms)^ReproductionPlan:\s*(.*?)^SandboxProfile:').Groups[1].Value
$sandboxProfileBlock = [regex]::Match($contractText, '(?ms)^SandboxProfile:\s*(.*?)^DynamicReproductionLifecycleProfile:').Groups[1].Value
$resourceLifecycleProfileBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionLifecycleProfile:\s*(.*?)^EnvironmentRecipe:').Groups[1].Value
$environmentRecipeBlock = [regex]::Match($contractText, '(?ms)^EnvironmentRecipe:\s*(.*?)^EnvironmentCheck:').Groups[1].Value
$environmentCheckBlock = [regex]::Match($contractText, '(?ms)^EnvironmentCheck:\s*(.*?)^SandboxEnvironment:').Groups[1].Value
$sandboxEnvironmentBlock = [regex]::Match($contractText, '(?ms)^SandboxEnvironment:\s*(.*?)^PlanIssueItem:').Groups[1].Value
$planIssueItemBlock = [regex]::Match($contractText, '(?ms)^PlanIssueItem:\s*(.*?)^SandboxPolicyDecision:').Groups[1].Value
$sandboxPolicyDecisionBlock = [regex]::Match($contractText, '(?ms)^SandboxPolicyDecision:\s*(.*?)^SandboxCommandRecord:').Groups[1].Value
$sandboxCommandRecordBlock = [regex]::Match($contractText, '(?ms)^SandboxCommandRecord:\s*(.*?)^CleanupResult:').Groups[1].Value
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
foreach ($field in @('meta:', 'network_mode:', 'allowed_egress_refs:', 'isolation_policy_refs:', 'cpu_limit_millicores:', 'memory_limit_bytes:', 'disk_limit_bytes:', 'pid_limit:', 'max_requested_execution_ms:', 'created_at:')) {
    if (-not $sandboxProfileBlock.Contains($field)) {
        Add-Failure "missing SandboxProfile field: $field"
    }
}
foreach ($field in @('meta:', 'preflight_budget_ref:', 'preflight_budget_source:', 'max_new_attempts:', 'created_at:')) {
    if (-not $resourceLifecycleProfileBlock.Contains($field)) {
        Add-Failure "missing DynamicReproductionLifecycleProfile field: $field"
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
foreach ($field in @('meta:', 'action_id:', 'request_ref:', 'reproduction_plan_ref:', 'environment_recipe_ref:', 'environment_ref:', 'executable:', 'arguments:', 'working_directory:', 'environment_binding_refs:', 'stdin_ref:', 'secret_refs:', 'command_digest:', 'redaction_status:', 'created_at:')) {
    if (-not $sandboxCommandRecordBlock.Contains($field)) { Add-Failure "missing SandboxCommandRecord field: $field" }
}
foreach ($field in @('meta:', 'request_ref:', 'environment_refs:', 'resource_refs:', 'status:', 'failure_reason:', 'finished_at:')) {
    if (-not $cleanupResultBlock.Contains($field)) { Add-Failure "missing CleanupResult field: $field" }
}
foreach ($field in @('event_id:', 'sequence:', 'action_id:', 'event_type:', 'actor:', 'environment_ref:', 'environment_recipe_ref:', 'poc_candidate_ref:', 'command_ref:', 'command_digest:', 'redaction_status:', 'input_refs:', 'output_refs:', 'exit_code:', 'safe_message:', 'occurred_at:')) {
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
    REGISTER_WORK = 'ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, RECOVERY'
    CHANGE_WORK_STATE = 'ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    START_ATTEMPT = 'ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    CANCEL_WORK = 'ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY'
    READ_CODE = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE'
    RUN_TOOL = 'REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR'
    CALL_LLM = 'HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, R7_AGENT'
    FETCH_POLICY = 'POLICY_COLLECTOR'
    REQUEST_DYNAMIC_REPRO = 'VERIFICATION'
    RUN_SANDBOX = 'R7_SETUP_AUTOMATION'
    SAVE_RESULT = 'ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, PRIMITIVE_ADMISSION_RUNTIME, R7_AGENT, R7_SETUP_AUTOMATION, SANDBOX_CONTROLLER, REPRODUCTION_SESSION_MANAGER, RECOVERY'
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
    if (-not $block.Contains('R7_AGENT')) {
        Add-Failure 'R7_AGENT missing from LLM call role enum'
    }
}
$dynamicReproductionResultBlock = [regex]::Match($contractText, '(?ms)^DynamicReproductionResult:\s*(.*?)^```').Groups[1].Value
$dynamicPlanIssuesCount = [regex]::Matches($dynamicReproductionResultBlock, '(?m)^\s+plan_issues:').Count
if ($dynamicPlanIssuesCount -ne 1) {
    Add-Failure "DynamicReproductionResult.plan_issues must be defined exactly once; found $dynamicPlanIssuesCount"
}
if (-not $dynamicReproductionResultBlock.Contains('plan_issues: [PlanIssueItem]')) {
    Add-Failure 'DynamicReproductionResult.plan_issues must use PlanIssueItem'
}

foreach ($blockInfo in @(
    @{ Name = 'LLMCallSpec'; Block = $llmSpecBlock },
    @{ Name = 'LLMInvocationRequest'; Block = $llmRequestBlock }
)) {
    if (-not $blockInfo.Block.Contains('token_budget: integer | null')) {
        Add-Failure "$($blockInfo.Name) token_budget must be an optional planning value"
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
$analysisRunStateBlock = [regex]::Match($contractText, '(?ms)^AnalysisRunState:\s*(.*?)^ProposalProcessState:').Groups[1].Value
if (-not $analysisRunStateBlock.Contains('eval_config_refs: [RunStoredDataRef | StoredDataRef]')) {
    Add-Failure 'AnalysisRunState.eval_config_refs must freeze exact evaluation configuration references'
}
$requiredAnalysisResultFields = @('hypothesis_duplicate_review_refs:', 'finding_refs:', 'verification_refs:', 'cwe_label_refs:', 'technical_review_refs:', 'rule_scope_review_refs:', 'policy_record_refs:', 'dynamic_request_refs:', 'dynamic_result_refs:', 'environment_recipe_refs:', 'sandbox_environment_refs:', 'agent_log_refs:', 'sandbox_policy_decision_refs:', 'cleanup_result_refs:', 'poc_candidate_refs:', 'poc_refs:', 'report_draft_refs:', 'llm_invocation_log_refs:', 'action_decision_refs:', 'work_state_refs:', 'work_attempt_refs:', 'transition_commit_refs:', 'eval_config_refs:', 'debug_trace_ref:')
foreach ($field in $requiredAnalysisResultFields) {
    if (-not $analysisRunResultBlock.Contains($field)) {
        Add-Failure "missing AnalysisRunResult handoff field: $field"
    }
}
if (-not $analysisRunResultBlock.Contains('eval_config_refs: [RunStoredDataRef | StoredDataRef]')) {
    Add-Failure 'AnalysisRunResult.eval_config_refs must use exact versioned references'
}

$contextLimitsBlock = [regex]::Match($contractText, '(?ms)^ContextRetrievalLimits:\s*(.*?)^```').Groups[1].Value
if ($contextLimitsBlock.Contains('token_budget:')) {
    Add-Failure 'ContextRetrievalLimits must use byte limits and must not enforce a token cap'
}

$requiredR8CommonContractRules = @(
    '`ActionCheck.check_type=BUDGET`은 versioned runtime policy의 시간·비용·호출·work·retry·repair·Gate 보완 한도만 검사한다.',
    '`LLMCallSpec.token_budget`과 `LLMInvocationRequest.token_budget`은 provider 호출에 예상되는 사용량을 기록하는 0 이상의 선택 계획값이다.',
    '`AnalysisRunResult.purpose=PRODUCTION`이면 `eval_config_refs=[]`이고 평가 설정을 생산 판정·Gate·Primitive admission·Reporter의 입력으로 사용하지 않는다.',
    '분석 종료 시 `AnalysisRunResult.eval_config_refs`는 시작 상태의 전체 집합과 중복 없이 set-equal해야 하며 빠진 값·추가 값·이름만 같은 다른 revision을 허용하지 않는다.',
    '두 `purpose=EVALUATION` 결과는 `eval_config_refs`가 exact reference 기준으로 set-equal할 때만 직접 비교한다.',
    '이 목록과 오프라인 사람 정답은 평가용 provenance일 뿐 Gate·Primitive·Reporter 입력이나 자동화된 Human Review 결정이 아니다.'
)
foreach ($rule in $requiredR8CommonContractRules) {
    if (-not $contractText.Contains($rule)) {
        Add-Failure "missing R8 common contract rule: $rule"
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
    '공식 부재 확인 또는 수집 실패인데 `ALLOW` 출력',
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
    '`RUN_SANDBOX` 허가 뒤 request·requirements·current exact plan·`sandbox_profile_ref`·`DynamicReproductionLifecycleProfile` revision 중 하나가 바뀜'
    'Sandbox 내부 command가 host·Docker socket·secret·미허용 egress에 접근하려 함'
    '동적 결과의 recipe·환경·AgentLog·candidate·PoC·cleanup attempt 또는 digest가 다름'
    '`COMMAND_STARTED`와 `COMMAND_FINISHED`의 command ref·digest·action·attempt·environment가 다르거나 redaction이 유효하지 않음'
    'Verification 또는 R7 Agent가 `DynamicReproductionResult`를 직접 저장'
)
foreach ($marker in $authorityScenarioMarkers) {
    if (-not $securityText.Contains($marker)) {
        Add-Failure "missing R4-03 authority scenario: $marker"
    }
}

$sandboxReviewPatterns = @(
    @{
        Name = 'Sandbox Controller enforces the R7 sandbox admission boundary'
        Pattern = '(?s)`action_decision_ref`는 plan 입력 부족·모순.*?pre-boundary 결과에서만 `null`.*?`action_decision_ref\.record_id`는 R7 호출자의 권한·상태·예산.*?exact `DynamicReproductionRequest`.*?current `EnvironmentRequirements`.*?Sandbox Controller는 R7 소유 `sandbox_profile_ref`의 host, Docker daemon/socket, host mount·namespace, secret, 허용되지 않은 egress, 다른 workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간 수치를 강제.*?컨테이너 내부 command를 allowlist로 재판단하지 않는다'
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
        Pattern = '(?s)`dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`.*?`environment_requirements -> EnvironmentRequirements -> R7_AGENT`.*?`reproduction_plan -> ReproductionPlan -> R7_AGENT`.*?`environment_recipe -> EnvironmentRecipe -> R7_SETUP_AUTOMATION`.*?`sandbox_command_record -> SandboxCommandRecord -> REPRODUCTION_SESSION_MANAGER`.*?`agent_log -> AgentLog -> REPRODUCTION_SESSION_MANAGER`.*?`poc_bundle -> PoCBundle -> REPRODUCTION_SESSION_MANAGER`.*?`dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_SESSION_MANAGER`'
    },
    @{
        Name = 'R7 sandbox and R8 lifecycle profiles have distinct exact contracts'
        Pattern = '(?s)SandboxProfile:.*?cpu_limit_millicores: integer.*?memory_limit_bytes: integer.*?disk_limit_bytes: integer.*?pid_limit: integer.*?max_requested_execution_ms: integer.*?DynamicReproductionLifecycleProfile:.*?preflight_budget_source: WORK_REMAINING_TIME.*?max_new_attempts: integer.*?`data_kind=sandbox_profile`.*?R7 sandbox policy owner.*?`data_kind=dynamic_reproduction_lifecycle_profile`.*?R8 evaluation/budget owner.*?CPU·RAM·disk·PID·요청 가능 최대 시간은 이 R8 profile에 넣지 않는다.*?`ActionRequest.sandbox_profile_ref`.*?`SandboxPolicyDecision.sandbox_profile_ref`.*?`ActionRequest.resource_profile_ref`.*?`SandboxPolicyDecision.resource_profile_ref`'
    },
    @{
        Name = 'AgentLog command events bind the same exact command'
        Pattern = '(?s)SandboxCommandRecord:.*?command_digest: string.*?redaction_status: REDACTED \| NOT_REQUIRED.*?`COMMAND_STARTED`와 대응하는 `COMMAND_FINISHED`.*?동일한 exact `SandboxCommandRecord.command_ref`·`command_digest`, `action_id`, `environment_ref`, `environment_recipe_ref`.*?secret 원문은 저장하지 않고 opaque `secret_refs`.*?검사 실패 command나 log는 저장하지 않는다'
    },
    @{
        Name = 'Dynamic retry lifecycle distinguishes session and external resume'
        Pattern = '(?s)같은 R7 Agent session의 command·PoC·환경 조정.*?상태 전이나 새 attempt를 만들지 않는다.*?새 `attempt_id`, `trigger=RETRY`.*?새 `attempt_id`, `trigger=RESUME`.*?과거 attempt artifact를 current 결과에 섞지 않는다'
    }
)
foreach ($rule in $sandboxReviewPatterns) {
    if (-not [regex]::IsMatch($contractText, $rule.Pattern)) {
        Add-Failure "missing or weakened PR #27 Sandbox review rule: $($rule.Name)"
    }
}

$environmentHandoffPatterns = @(
    @{
        Name = 'R6 owns the immutable request and R7 Agent owns requirements and plan'
        Pattern = '(?s)`DynamicReproductionRequest`는 R6 Verification.*?불변 record.*?`EnvironmentRequirements`와 `ReproductionPlan`은 R7 Reproduction Agent'
    },
    @{
        Name = 'reproduction plan binds current exact requirements'
        Pattern = '(?s)`ReproductionPlan`은 R7 Agent가.*?`sandbox_profile_ref`는 R6 request와 exact match.*?`environment_requirements_ref`는 같은 R7 attempt의 current requirements'
    },
    @{
        Name = 'RUN_SANDBOX freezes the exact request, requirements, plan, and profiles'
        Pattern = '(?s)`ActionRequest\.reproduction_plan_ref`는 current `DYNAMIC_REPRO` work·attempt의 current exact `ReproductionPlan`.*?`RUN_SANDBOX` action `input_refs`에는 exact `DynamicReproductionRequest`·current `EnvironmentRequirements`·current exact `ReproductionPlan`·`sandbox_profile_ref`·exact `DynamicReproductionLifecycleProfile`.*?`resource_profile_ref`도 같은 profile revision'
    },
    @{
        Name = 'pre-boundary plan is provenance and only PoC candidate and command are sandbox-generated'
        Pattern = '(?s)`EnvironmentRequirements`와 `ReproductionPlan`은 외부 경계 검사 전에 생성.*?PoC candidate와 command만 경계 승인 후 Sandbox 내부에서 생성.*?경계 전에 만든 plan은 command allowlist가 아니라 실행 provenance'
    },
    @{
        Name = 'actual environment compares every requirement'
        Pattern = '(?s)EnvironmentCheck:.*?status: MATCH \| MISMATCH \| NOT_CHECKED \| ERROR.*?SandboxEnvironment:.*?requirements_ref: StoredDataRef.*?checks: \[EnvironmentCheck\].*?모든 `requirement_id`를 정확히 한 번씩 포함'
    },
    @{
        Name = 'environment mismatch is resolved or returned without a false verdict'
        Pattern = '(?s)필수 item에 확인된 값 차이 또는 미확인이 있으면 환경 status는 `MISMATCH`.*?setup·비교 자체의 오류가 있으면 `ERROR`.*?필수 환경 요구사항 불일치.*?같은 R7 Agent session이면 현재 attempt.*?session 재시작은 새 `attempt_id`·`trigger=RETRY`.*?외부 수정 대기 해소 뒤 재개는 새 `attempt_id`·`trigger=RESUME`.*?한도 소진이면 `FAILED`'
    },
    @{
        Name = 'environment recipe is immutable and digest bound'
        Pattern = '(?s)`EnvironmentRecipe`는 current `DYNAMIC_REPRO` attempt의 binding record.*?불변 build recipe.*?`meta.hypothesis_id`와 `meta.attempt_id`는 반드시 현재 work·attempt 값.*?별도 Dependency Scanner나 R2 사전 package prefetch를 전제로 하지 않는다.*?`base_image_digest`는 시작 image.*?`built_image_digest`는 실제 build 또는 재사용한 완성 image.*?과거 성공 환경은 `baseline_recipe_ref`로만 참조.*?같은 `built_image_digest`를 가진 새 `EnvironmentRecipe` binding'
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
    'R7이 request·requirements·plan·`sandbox_profile_ref`·`DynamicReproductionLifecycleProfile`을 바꾸고 Sandbox 외부 경계 재검사를 생략함'
)
foreach ($marker in $environmentNegativeMarkers) {
    $rowPattern = '(?m)^\|\s*' + [regex]::Escape($marker) + '\s*\|'
    if ([regex]::Matches($securityText, $rowPattern).Count -ne 1) {
        Add-Failure "missing R6-R7 environment negative scenario: $marker"
    }
}

$orchestrationPath = Join-Path $repoRoot 'docs/architecture-v5/03-agent-roles-and-orchestration.md'
$orchestrationText = Get-Content -Raw -Encoding UTF8 -LiteralPath $orchestrationPath
$gatePath = Join-Path $repoRoot 'docs/architecture-v5/05-llm-gate-and-reporting.md'
$gateText = Get-Content -Raw -Encoding UTF8 -LiteralPath $gatePath
$chainingPath = Join-Path $repoRoot 'docs/architecture-v5/06-chaining.md'
$chainingText = Get-Content -Raw -Encoding UTF8 -LiteralPath $chainingPath
$requiredChainingAdmissionRules = @(
    '체이닝 재료 자격은 세 가지를 확인해 정한다',
    'current `PrimitiveAdmissionDecision.decision=ALLOW`',
    'Chaining Agent는 `rule_compliance`나 `evidence_links`를 읽어 금지 테스트 위반을 추정하지 않는다.',
    '확정된 금지 테스트 위반으로 `DENY`가 된 경우만 재료에서 제외된다.',
    '`WorkExecutionState.input_refs`에 함께 고정한다',
    '`source_admission_refs`에는 실제 match에 사용한 Primitive와 그 계보에서 재귀적으로 도달한 모든 admission decision을 중복 없이 기록하며',
    '`STALE_RESULT`로 저장을 거절하고 새 자식 가설을 만들지 않는다',
    '실제 match에 사용하지 않은 후보의 decision 변경만으로는 진행 중인 결과를 무효화하지 않는다.',
    '부모의 admission이 나중에 `DENY`로 바뀌면 파생 결과는 감사 기록으로만 보존하고'
)
foreach ($rule in $requiredChainingAdmissionRules) {
    if (-not $chainingText.Contains($rule)) {
        Add-Failure "missing Chaining admission rule in 06-chaining.md: $rule"
    }
}
$chainingDocResultBlock = [regex]::Match($chainingText, '(?ms)^ChainingResult:\s*(.*?)^```').Groups[1].Value
if (-not $chainingDocResultBlock.Contains('source_admission_refs:')) {
    Add-Failure '06-chaining.md ChainingResult is missing field: source_admission_refs:'
}
$chainingPrimitiveBlock = [regex]::Match($chainingText, '(?ms)^Primitive:\s*(.*?)^```').Groups[1].Value
if (-not $chainingPrimitiveBlock.Contains('admission_decision_ref:')) {
    Add-Failure '06-chaining.md Primitive is missing field: admission_decision_ref:'
}

$gateWikiPath = Join-Path $repoRoot 'docs/architecture-v5/wiki/gate-and-reporting.md'
$gateWikiText = Get-Content -Raw -Encoding UTF8 -LiteralPath $gateWikiPath
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
        Marker = '`FOUND`라도 핵심 출처가 누락되거나 정책이 `STALE | UNVERIFIED`이면 Rule·testing restriction·Scope·review는 `UNCERTAIN`, permission은 `DENY`이며 누락·최신성 문제를 구조화해 보존한다.'
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

# R5-03 후속이슈: Finding 생성 lifecycle과 Reporter handoff.
$requiredFindingLifecycleRules = @(
    @{ Name = 'gate doc defines Finding as a trusted-runtime normalization record'; Text = $gateText; Marker = '`Finding`은 새 취약점 판정 Gate가 아니라, 이미 검증된 upstream 결과를 하나의 current 취약점 결과로 정규화해 저장하는 record다.' },
    @{ Name = 'gate doc keeps Finding claim strength at or below verified upstream'; Text = $gateText; Marker = 'Finding의 모든 material claim 강도는 verified upstream evidence의 claim strength 이하여야 한다.' },
    @{ Name = 'gate doc separates Finding existence from Reporter eligibility'; Text = $gateText; Marker = '`current Finding 존재 + Reporter 차단 + report_draft_refs=[]`' },
    @{ Name = 'gate doc requires a current non-stale Finding for Reporter'; Text = $gateText; Marker = 'AND current non-stale Finding exists for this exact chain' },
    @{ Name = 'gate doc defines the stale Finding lifecycle'; Text = $gateText; Marker = '### stale Finding' },
    @{ Name = 'contract doc binds Finding to the committed exact chain without a new agent'; Text = $contractText; Marker = 'current Finding은 새 vulnerability verdict나 impact를 만드는 Gate가 아니라, 신뢰 runtime이 이미 `COMMITTED`된 exact upstream reference를 조립한 정규화 record다.' },
    @{ Name = 'contract doc adds no new Finding agent, action_type, or producer enum'; Text = $contractText; Marker = '이 작업은 새 autonomous Agent role, 새 `action_type` 또는 새 producer enum을 추가하지 않는다.' },
    @{ Name = 'contract doc resolves Finding storage binding in R4 B2'; Text = $contractText; Marker = '구체 binding은 [구현 모듈 맵](implementation/01-module-map.md) B2에 확정한다.' },
    @{ Name = 'security doc rejects mixing Finding creation with Reporter readiness'; Text = $securityText; Marker = '| Finding 생성 조건을 Reporter 6축 readiness와 동일하게 취급 |' },
    @{ Name = 'security doc blocks stale Finding reuse in Reporter'; Text = $securityText; Marker = '| Finding 정규화 전이거나 stale Finding으로 Reporter 호출 |' },
    @{ Name = 'overview canonical flow puts current Finding before Reporter'; Text = $overviewText; Marker = 'current Finding -> Reporter -> ReportDraft -> AnalysisRunResult -> Agent automation end' },
    @{ Name = 'canonical diagram shows trusted-runtime Finding normalization'; Text = $diagramText; Marker = 'NORM[FINDING_NORMALIZE - trusted runtime non-LLM work]' },
    @{ Name = 'wiki diagram shows trusted-runtime Finding normalization'; Text = $wikiDiagramText; Marker = 'NORM[FINDING_NORMALIZE - trusted runtime non-LLM work]' },
    @{ Name = 'gate wiki documents the Finding normalization step'; Text = $gateWikiText; Marker = '## Finding 정규화' }
)
foreach ($rule in $requiredFindingLifecycleRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing or weakened R5-03 follow-up Finding lifecycle rule: $($rule.Name)"
    }
}

# R7 cross-review: Finding closure metadata scope and normalization work agreement.
$findingClosurePaths = @(
    '05-llm-gate-and-reporting.md',
    '08-lightweight-data-contracts.md',
    '10-security-boundaries.md',
    'implementation/01-module-map.md',
    'wiki/gate-and-reporting.md'
)
foreach ($path in $findingClosurePaths) {
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot "docs/architecture-v5/$path")
    foreach ($marker in @('hypothesis-local artifact에 대해서만 동일 `meta.hypothesis_id`', '`ProgramPolicyRecord`, `PolicyCollectionResult` 등 hypothesis 비종속 정책 record에는 `hypothesis_id` 일치를 요구하지 않으며', '기존 exact `StoredDataRef`, `meta.workspace_id`·`meta.commit_id` 및 policy revision/provenance 계약')) {
        if (-not $text.Contains($marker)) { Add-Failure "missing Finding closure metadata scope in ${path}: $marker" }
    }
    if ($text -match 'upstream(?: record)?의? `meta.hypothesis_id`·`meta.workspace_id`·`meta.commit_id`') {
        Add-Failure "unscoped Finding upstream hypothesis match in $path"
    }
}
foreach ($text in @($gateWikiText, $diagramText, $wikiDiagramText)) {
    foreach ($marker in @('RULE_SCOPE_GATE → FINDING_NORMALIZE → Reporter readiness', '비-LLM normalization work', '새 autonomous Agent나 LLM Gate가')) {
        if (-not $text.Contains($marker)) { Add-Failure "missing Finding work cross-document rule: $marker" }
    }
    if ($text.Contains('Finding 생성은 새 Agent role·work·action을 추가하지 않으며')) {
        Add-Failure 'obsolete no-new-work Finding contract'
    }
}
Write-Output "Finding lifecycle cross-document checks: R7 closure scope (5 documents) and normalization work (Wiki + 2 diagrams)"

# R4 Finding storage: schema, exclusive output binding and current-only finalization.
$findingSchema = [regex]::Match($contractText, '(?ms)^Finding:\r?\n(.*?)^FindingConditionSource:').Groups[1].Value
foreach ($field in @('meta: RecordMeta', 'verification_result_ref: StoredDataRef', 'dynamic_result_ref: StoredDataRef', 'poc_ref: StoredDataRef', 'cwe_label_ref: StoredDataRef', 'technical_review_ref: StoredDataRef', 'rule_scope_impact_review_ref: StoredDataRef', 'policy_collection_result_ref: StoredDataRef', 'policy_record_ref: StoredDataRef | null', 'evidence_refs: [StoredDataRef]', 'condition_sources: [FindingConditionSource]')) {
    if (-not $findingSchema.Contains($field)) { Add-Failure "missing canonical Finding field: $field" }
}
$requiredFindingStorageRules = @(
    'RULE_SCOPE_GATE | FINDING_NORMALIZE | REPORT_DRAFT',
    '`RULE_SCOPE_GATE`의 `SUCCEEDED`는 정확히 하나의 `RuleScopeImpactReview.record_id`를 가리킨다.',
    '`FINDING_NORMALIZE`의 `SUCCEEDED`는 정확히 하나의 `Finding.record_id`를 가리킨다.',
    '`finding -> Finding -> VERIFICATION`',
    'versioned result-owner registry에 고정된 이 service의 exact `requester_identity_ref`',
    'source_path: string',
    'status: EMPTY | CURRENT | STALE',
    'stale_finding_ref: StoredDataRef | null',
    'index의 expected `record_id`·`state_version`과 모든 upstream current pointer/generation을 함께 비교한다.',
    'normalization commit과 invalidation은 같은 index CAS로 직렬화',
    '`AnalysisRunResult.finding_refs`는 확정 시 각 `CURRENT` index',
    '`current Finding 존재 + Reporter blocked + report_draft_refs=[]`는 정상적인 `AnalysisRunResult`다.',
    '다른 필수 작업이 완료되면 `COMPLETE`가 가능하다.'
)
foreach ($rule in $requiredFindingStorageRules) {
    if (-not $contractText.Contains($rule)) { Add-Failure "missing R4 Finding storage rule: $rule" }
}
$findingModuleText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/implementation/01-module-map.md')
foreach ($rule in @('`FINDING_NORMALIZE`', '`finding -> Finding -> VERIFICATION`', '`FindingIndexState`', 'Reporter blocked이면 `report_draft_refs=[]`')) {
    if (-not $findingModuleText.Contains($rule)) { Add-Failure "missing Finding module binding: $rule" }
}
foreach ($obsolete in @('Reporter가 current `ReportDraft`를 저장하고 해당 `REPORT_DRAFT` work를 종료한 뒤, 신뢰 runtime은', 'R4 storage binding 대기', '**R4 대기(storage binding)**')) {
    if ($contractText.Contains($obsolete) -or $findingModuleText.Contains($obsolete)) { Add-Failure "obsolete Finding storage contract: $obsolete" }
}
Write-Output "R4 Finding storage rules: $($requiredFindingStorageRules.Count)"

$requiredVerificationChainingContracts = @(
    'VerificationAssignment:',
    'verification_assignment_ref:',
    'ChainingResult:',
    'source_result_refs:',
    'source_admission_refs:',
    'considered_primitive_refs:',
    'input_primitive_refs:',
    'primitive_match_candidates:',
    'chained_hypothesis_proposals:',
    'excluded_lineage_refs:',
    'LineageExclusion:',
    'excluded_primitive_ref:',
    'excluded_by_ref:',
    'reason_code: ANCESTOR_REUSE',
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
    $activeText = Get-Content -Raw -Encoding UTF8 -LiteralPath $check.Path
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
foreach ($field in @('upstream_result_ref:', 'downstream_input_ref:', 'matched_input_id:', 'parent_hypothesis_ids:', 'parent_verification_refs:', 'workspace_id:', 'commit_id:', 'evidence_refs:', 'candidate_state: UNVALIDATED')) {
    if (-not $primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate is missing field: $field"
    }
}
foreach ($field in @('normalized_fingerprint:', 'match_kind:', 'input_primitive_index_refs:', 'upstream_provided_ref:', 'matched_requirement_id:', 'asset_check:', 'entity_check:', 'endpoint_check:', 'privilege_check:', 'data_check:', 'attack_order_check:', 'restriction_check:', 'unresolved_conditions:')) {
    if ($primitiveMatchBlock.Contains($field)) {
        Add-Failure "PrimitiveMatchCandidate still contains obsolete field: $field"
    }
}

$noMatchReasonBlock = [regex]::Match($contractText, '(?ms)^NoMatchReason:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('upstream_result_ref:', 'downstream_input_ref:', 'checked_input_id:', 'reason_code:', 'detail:')) {
    if (-not $noMatchReasonBlock.Contains($field)) {
        Add-Failure "NoMatchReason is missing field: $field"
    }
}
if ($noMatchReasonBlock.Contains('DUPLICATE_COMBINATION')) {
    Add-Failure 'NoMatchReason must not treat an already-stored combination as a match failure'
}

$chainingResultBlock = [regex]::Match($contractText, '(?ms)^ChainingResult:\s*(.*?)^```').Groups[1].Value
foreach ($field in @('source_result_refs:', 'source_admission_refs:', 'considered_primitive_refs:', 'input_primitive_refs:', 'primitive_match_candidates:', 'chained_hypothesis_proposals:', 'excluded_lineage_refs:', 'no_match_reasons:', 'errors:')) {
    if (-not $chainingResultBlock.Contains($field)) {
        Add-Failure "ChainingResult is missing field: $field"
    }
}
foreach ($field in @('trigger:', 'input_primitive_index_refs:', 'bounded_stop_reason:')) {
    if ($chainingResultBlock.Contains($field)) {
        Add-Failure "ChainingResult still contains obsolete field: $field"
    }
}

$requiredChainingExclusionRules = @(
    '`considered_primitive_refs`는 Runtime이 `REGISTER_WORK(work_type=CHAINING)`에서 고정한 exact Primitive 입력 집합과 set-equal하다.',
    '`source_admission_refs`는 이 실제 사용 decision 집합과 중복 없이 set-equal해야 한다.',
    '일반 index 갱신이나 실제 match에 사용하지 않은 후보의 decision 변경만으로는 기존 work를 거절하지 않지만, `source_admission_refs` 중 하나가 current가 아니거나 `DENY`로 바뀌면 오염된 재료의 사용을 막기 위해 진행 중인 결과를 거절한다.',
    '`input_primitive_refs`는 `primitive_match_candidates`의 upstream/downstream exact reference 합집합과 set-equal하다.',
    '`considered_primitive_refs`, `input_primitive_refs`, `source_result_refs`, `source_admission_refs`와 candidate별 `parent_hypothesis_ids`, `parent_verification_refs`는 각각 중복이 없어야 한다.',
    '`source_result_refs`는 `input_primitive_refs`가 가리키는 Primitive들의 `source_verification_ref`와 non-null `technical_review_ref` 합집합과 set-equal하고 모두 같은 `SAVE_RESULT.input_refs`에 포함되어야 한다.',
    '각 candidate의 `parent_hypothesis_ids`는 그 upstream/downstream Primitive의 `source_hypothesis_id` 합집합, `parent_verification_refs`는 두 Primitive의 `source_verification_ref` 합집합과 각각 set-equal해야 한다.',
    '`excluded_primitive_ref`는 `considered_primitive_refs`에 포함되고 `input_primitive_refs`와 모든 match candidate reference에는 포함되지 않아야 한다.',
    '`excluded_by_ref`는 `considered_primitive_refs`와 `input_primitive_refs`에 모두 포함되고 같은 결과의 `excluded_primitive_ref` 집합에는 포함되지 않아야 한다.',
    'Runtime은 §06의 제외 규칙(성립한 match의 후보에서 양방향 재귀 탐색)으로 기대 제외 쌍을 다시 계산하고 `excluded_lineage_refs`와 set-equal한지 검사한다.',
    '`origin=CHAINING`이면 `observed_facts=[]`만 허용한다.',
    '`ChainingResult.considered_primitive_refs`, `source_admission_refs`와 `excluded_lineage_refs` 추가, `PrimitiveMatchCandidate`의 필드 제거, `no_match_reasons`의 `NoMatchReason` 전환은 기존 결과의 필수 필드를 바꾸므로 새 MAJOR schema로 배포한다.',
    '`primitive_match_id`는 분석 전체에서 유일하고 같은 `(upstream_result_ref, downstream_input_ref, matched_input_id)` 조합도 중복 저장하지 않는다.',
    '`(analysis_id, upstream_result_ref, downstream_input_ref, matched_input_id)`에 저장 시점 uniqueness를 강제한다.',
    'Chaining work는 새 Primitive 저장을 계기로 등록한다.'
)
foreach ($rule in $requiredChainingExclusionRules) {
    if (-not $contractText.Contains($rule)) {
        Add-Failure "missing exact Chaining exclusion rule: $rule"
    }
}

$requiredChainingWikiRules = @(
    '`considered_primitive_refs`',
    '`excluded_lineage_refs`',
    '`origin=CHAINING` 자식의 `observed_facts`는 빈 목록',
    '`source_admission_refs`',
    '일반적인 새 Primitive·index 변경과 사용하지 않은 후보의 decision 변경은 진행 중 입력을 바꾸지 않고 다음 work에서 처리합니다.'
)
foreach ($rule in $requiredChainingWikiRules) {
    if (-not ($chainingWikiText.Contains($rule) -or $commonWikiText.Contains($rule))) {
        Add-Failure "Wiki is missing Chaining input/exclusion rule: $rule"
    }
}

if ($staticText.Contains('저장된 ACTIVE Primitive')) {
    Add-Failure 'static fact layer still refers to obsolete ACTIVE Primitive state'
}

$requiredStaticPrimitiveAdmissionRules = @(
    '같은 Verification의 current `PrimitiveAdmissionDecision=ALLOW`',
    '`Primitive.admission_decision_ref`는 그 current exact ALLOW decision을 가리킨다.',
    'R4 `PRIMITIVE_ADMISSION_RUNTIME`의 입력이며, confirmed `FAIL`은 `PrimitiveAdmissionDecision=DENY`로 매핑'
)
foreach ($rule in $requiredStaticPrimitiveAdmissionRules) {
    if (-not $staticText.Contains($rule)) {
        Add-Failure "static fact layer is missing Primitive admission authority rule: $rule"
    }
}

$decisionText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/decisions/ADR-001-verification-owned-chaining-admission.md')
if ($decisionText.Contains('lookup 시 ACTIVE 확인')) {
    Add-Failure 'Chaining ADR still uses obsolete ACTIVE-based Primitive lookup'
}

$activeDocumentationText = (($markdownFiles | Where-Object { $_.FullName -notmatch '[\\/]archive[\\/]' } | ForEach-Object { Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName }) -join "`n")
foreach ($obsoleteRule in @(
    'current pointer 갱신으로 오래된 Chaining 결과를 거절',
    '원자적 current pointer 갱신 실패로 결과·child proposal을 `STALE_RESULT` 처리',
    'commit 직전에 current head를 재검사해 in-flight stale 결과를 차단',
    'exact current record가 아닌 결과는 저장할 수 없습니다.',
    'exact current record를 저장 시 재확인'
)) {
    if ($activeDocumentationText.Contains($obsoleteRule)) {
        Add-Failure "active documentation still contains obsolete Chaining invalidation rule: $obsoleteRule"
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
    '| N4 | TRUE + Technical `ACCEPT`, 정책 수집 또는 Rule Scope 검토가 아직 종료되지 않음 |',
    '| N5 | TRUE + Technical `ACCEPT` + Rule Scope의 다른 판단 `FAIL | UNCERTAIN | DENY`, testing restriction은 `PASS | UNCERTAIN` |',
    '| N6 | TRUE + Technical `ACCEPT` + Rule Scope review가 Reporter 6축 readiness 전부 충족 |',
    '| N7 | result가 있는 TRUE Primitive + result가 없는 HOLD Primitive |',
    '| N8 | result가 있는 서로 다른 TRUE Primitive 둘 |',
    '| N9 | TRUE+TRUE 입력 중 한 부모가 Technical 비정상이거나 direct·ancestor current `PrimitiveAdmissionDecision=ALLOW`를 충족하지 않음 |',
    '| N10 | match의 entity 또는 privilege 충족 근거가 없음 |',
    '| N10-A | 성립한 match의 후보가 양방향 계보에서 이미 사용한 Primitive를 같은 결과에서 다시 사용 |',
    '| N10-B | `excluded_primitive_ref`가 고정된 `considered_primitive_refs` 밖이거나 실제 match에 다시 포함됨 |',
    '| N10-C | `excluded_by_ref`가 같은 work 입력이 아니거나 실제 match에 사용되지 않았거나 자신도 제외됐거나 계보가 제외 대상을 포함하지 않음 |',
    '| N10-D | exclusion pair가 중복되거나 reason code·analysis·workspace·commit이 다름 |',
    '| N10-E | CHAINING 자식이 `observed_facts`를 채우거나 부모 계보에서 검증 시작점을 복원할 수 없음 |',
    '| N10-F | `source_result_refs` 또는 match candidate의 parent 가설·Verification 목록이 실제 입력 Primitive와 다르거나 중복됨 |',
    '| N10-G | `considered_primitive_refs` 또는 `input_primitive_refs`에 같은 exact reference가 중복됨 |',
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
    '`testing_restriction_compliance`는 `rule_compliance`와 독립된 판정 축이다.',
    'current `PrimitiveAdmissionDecision(decision=ALLOW)`',
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
    $ruleExecutionDecisionText = Get-Content -Raw -Encoding UTF8 -LiteralPath $ruleExecutionDecisionPath
    foreach ($marker in @('상태: `ACCEPTED`', 'RunMeta', 'RuleExecutionRecord', 'ToolRunResult.tool_kind', 'ToolSource.attempt_id', '새 MAJOR schema', 'R2:', 'R4:', 'R8:')) {
        if (-not $ruleExecutionDecisionText.Contains($marker)) {
            Add-Failure "ADR-006 is missing decision marker: $marker"
        }
    }
}
$decisionIndexText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/decisions/README.md')
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

$glossaryText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/GLOSSARY.md')
$reviewChecklistText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/governance/REVIEW_CHECKLIST.md')
$issueCatalogText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/ISSUE_CATALOG.md')
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
    $staticFactDecisionText = Get-Content -Raw -Encoding UTF8 -LiteralPath $staticFactDecisionPath
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
    $cweLabelDecisionText = Get-Content -Raw -Encoding UTF8 -LiteralPath $cweLabelDecisionPath
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
        Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/quick-guide.md'))
        Marker = 'R5-01 CWE_LABELING이 exact Verification에 맞는 current CWELabel 생성'
    }
)
foreach ($rule in $requiredCweLabelCrossDocumentRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing R5-01 CWE labeling cross-document rule: $($rule.Name)"
    }
}

$playbookQuestionTemplateBlock = [regex]::Match($contractText, '(?ms)^PlaybookQuestionTemplate:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$verificationPlaybookBlock = [regex]::Match($contractText, '(?ms)^VerificationPlaybook:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$playbookPolicyItemBlock = [regex]::Match($contractText, '(?ms)^PlaybookPolicyItem:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$playbookPolicyBlock = [regex]::Match($contractText, '(?ms)^PlaybookPolicy:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$appliedPlaybookQuestionBlock = [regex]::Match($contractText, '(?ms)^AppliedPlaybookQuestion:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$playbookApplicationBlock = [regex]::Match($contractText, '(?ms)^PlaybookApplication:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value

$requiredPlaybookContractFields = @(
    @{ Contract = 'PlaybookQuestionTemplate'; Block = $playbookQuestionTemplateBlock; Fields = @('template_key: string', 'question: string') },
    @{ Contract = 'VerificationPlaybook'; Block = $verificationPlaybookBlock; Fields = @('falsification_question_templates: [PlaybookQuestionTemplate]') },
    @{ Contract = 'PlaybookPolicyItem'; Block = $playbookPolicyItemBlock; Fields = @('vulnerability_type: string', 'playbook_ref: StoredDataRef') },
    @{ Contract = 'PlaybookPolicy'; Block = $playbookPolicyBlock; Fields = @('common_playbook_ref: StoredDataRef', 'type_playbooks: [PlaybookPolicyItem]', 'approved_by: string', 'approved_at: timestamp') },
    @{ Contract = 'AppliedPlaybookQuestion'; Block = $appliedPlaybookQuestionBlock; Fields = @('template_key: string', 'question_id: string', 'question: string') },
    @{ Contract = 'PlaybookApplication'; Block = $playbookApplicationBlock; Fields = @('verification_work_id: string', 'verification_generation: integer', 'hypothesis_ref: StoredDataRef', 'proposal_ref: StoredDataRef', 'policy_ref: StoredDataRef', 'playbook_ref: StoredDataRef', 'selection: COMMON | TYPE_SPECIFIC', 'selected_type: string | null', 'selection_reason: TYPE_MATCH | NO_TYPE | MULTIPLE_TYPES | TYPE_NOT_ALLOWED', 'questions: [AppliedPlaybookQuestion]') },
    @{ Contract = 'VerificationResult'; Block = $verificationResultBlock; Fields = @('playbook_ref: StoredDataRef', 'playbook_application_ref: StoredDataRef') }
)
foreach ($contract in $requiredPlaybookContractFields) {
    if ([string]::IsNullOrWhiteSpace($contract.Block)) {
        Add-Failure "missing playbook contract block: $($contract.Contract)"
        continue
    }
    foreach ($field in $contract.Fields) {
        if (-not $contract.Block.Contains($field)) {
            Add-Failure "$($contract.Contract) is missing playbook field: $field"
        }
    }
}

$requiredPlaybookApplicationRules = @(
    @{ Name = 'Verification work registration pins policy and application'; Marker = '`REGISTER_WORK(work_type=VERIFICATION)` 시 trusted runtime은 exact `VulnerabilityHypothesis`와 그 `proposal_ref`, current exact `PlaybookPolicy`를 읽고' },
    @{ Name = 'Verification registration key excludes its derived application'; Marker = 'registration 과정에서 새로 생기는 application reference 자체는 `dedupe_key`에 넣지 않고 application의 원본인 hypothesis·proposal·policy·playbook reference를 넣는다.' },
    @{ Name = 'duplicate Verification registration reuses its application'; Marker = '같은 key의 work가 있으면 새 application을 만들지 않고 기존 work와 그 work에 고정된 application을 반환한다.' },
    @{ Name = 'registered hypothesis has no singular vulnerability type'; Marker = '등록된 `VulnerabilityHypothesis`에는 단일 `vulnerability_type` 필드가 없다.' },
    @{ Name = 'selection reads exact proposal candidates'; Marker = '선택 runtime은 `VulnerabilityHypothesis.proposal_ref`가 가리키는 exact `HypothesisProposal.vulnerability_type_candidates`만 읽는다.' },
    @{ Name = 'selection has explicit common fallbacks'; Marker = '후보가 없으면 `NO_TYPE`, 둘 이상이면 `MULTIPLE_TYPES`, 하나지만 policy에 없으면 `TYPE_NOT_ALLOWED`로 current COMMON revision을 선택한다.' },
    @{ Name = 'playbook application binds the Verification work'; Marker = '`PlaybookApplication`은 위 선택을 특정 Verification work에 고정한 runtime record다.' },
    @{ Name = 'template questions receive fresh global IDs'; Marker = '각 항목에 새 전역 `question_id`를 발급한다.' },
    @{ Name = 'all Verification actors use one exact application'; Marker = 'Verification Agent의 직접 검증, `PRO_EVIDENCE`, `CON_EVIDENCE`, final Verification 합성 호출 및 `SAVE_RESULT(result_kind=verification_result)`는 모두 해당 Verification work에 고정된 동일한 policy·playbook·application reference를 사용해야 한다.' },
    @{ Name = 'final question result set is exact union'; Marker = 'exact `VulnerabilityHypothesis.falsification_questions[].question_id`와 exact `PlaybookApplication.questions[].question_id`의 중복 없는 합집합과 set-equal해야 한다.' },
    @{ Name = 'policy and application are runtime-owned'; Marker = '`PlaybookApplication`도 Agent의 `SAVE_RESULT` 출력이 아니라 `REGISTER_WORK(work_type=VERIFICATION)` runtime이 work와 함께 만드는 고정 입력 record다.' },
    @{ Name = 'playbook application requires a new major schema'; Marker = '`PlaybookQuestionTemplate`, `PlaybookPolicy`, `PlaybookApplication`과 `VerificationResult.playbook_application_ref`는 새 필수 계약이므로 새 MAJOR schema에서만 사용한다.' },
    @{ Name = 'old playbook data is not inferred'; Marker = '과거 플레이북 문자열이나 Verification 결과에 template key·policy·application·질문 ID를 추정해 채우지 않는다.' }
)
foreach ($rule in $requiredPlaybookApplicationRules) {
    if (-not $contractText.Contains($rule.Marker)) {
        Add-Failure "missing playbook application contract rule: $($rule.Name)"
    }
}

$verificationWikiText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/verification-and-dynamic.md')
$requiredPlaybookCrossDocumentRules = @(
    @{ Name = 'role document defines registry runtime'; Text = $orchestrationText; Marker = '| Playbook Registry Runtime |' },
    @{ Name = 'role document fixes one question set'; Text = $orchestrationText; Marker = '같은 application 질문 집합을 사용하는지 검사' },
    @{ Name = 'Verification document separates evaluation evidence from operational approval'; Text = $verificationText; Marker = 'R8의 versioned evaluation corpus는 우선 지원할 취약점 유형을 정하는 평가 근거이고, 운영에서 실제 허용할 유형과 exact 플레이북 revision의 연결은 사람이 승인한 current `PlaybookPolicy`로 확정한다.' },
    @{ Name = 'Verification document defines exact type selection'; Text = $verificationText; Marker = '후보가 정확히 하나이고 current `PlaybookPolicy`에 같은 유형의 mapping이 있을 때만 해당 exact `TYPE_SPECIFIC` revision을 선택한다.' },
    @{ Name = 'Verification document requires one application question set'; Text = $verificationText; Marker = 'final 질문 결과는 가설 자체의 반증 질문과 application 질문의 합집합을 빠짐없이 정확히 한 번씩 처리해야 한다.' },
    @{ Name = 'security rejects guessed singular type'; Text = $securityText; Marker = '등록 가설에 없는 단일 `vulnerability_type`을 추정하거나 여러 type 후보 중 하나를 Agent가 선택' },
    @{ Name = 'security rejects different applications'; Text = $securityText; Marker = 'Pro·Con·최종 합성이 서로 다른 `PlaybookApplication` 또는 질문 ID를 사용' },
    @{ Name = 'security scenario N31 exists'; Text = $securityText; Marker = '| N31 | 가설 type 후보가 없거나 여러 개인데 TYPE_SPECIFIC 플레이북을 선택 |' },
    @{ Name = 'security scenario N32 exists'; Text = $securityText; Marker = '| N32 | policy에 없는 type 또는 policy와 다른 playbook revision을 선택 |' },
    @{ Name = 'security scenario N33 exists'; Text = $securityText; Marker = '| N33 | 플레이북 질문 template가 application에서 빠지거나 다른 문장·중복 ID로 저장됨 |' },
    @{ Name = 'security scenario N34 exists'; Text = $securityText; Marker = '| N34 | Verification 결과가 hypothesis 질문만 처리하고 application 질문을 누락 |' },
    @{ Name = 'Wiki explains exact playbook selection'; Text = $commonWikiText; Marker = '사람이 승인한 `PlaybookPolicy`가 유형과 exact 플레이북 수정본을 연결' },
    @{ Name = 'Wiki explains the applied question binding'; Text = $commonWikiText; Marker = '이번 검증에서 사용한 policy·playbook과 새로 발급한 질문 ID는 `PlaybookApplication`으로 묶어 work 입력에 고정합니다.' },
    @{ Name = 'Verification Wiki records both exact refs'; Text = $verificationWikiText; Marker = '`VerificationResult`는 exact `playbook_ref`와 `playbook_application_ref`를 함께 기록합니다.' },
    @{ Name = 'Verification Wiki explains template keys'; Text = $verificationWikiText; Marker = '플레이북의 `template_key`는 사람이 읽는 이름일 뿐 실제 질문 ID가 아닙니다.' },
    @{ Name = 'glossary explains policy'; Text = $glossaryText; Marker = '| `PlaybookPolicy` |' },
    @{ Name = 'glossary explains application'; Text = $glossaryText; Marker = '| `PlaybookApplication` |' }
)
foreach ($rule in $requiredPlaybookCrossDocumentRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing playbook application cross-document rule: $($rule.Name)"
    }
}

$playbookGuidePath = Join-Path $repoRoot 'docs/architecture-v5/verification-playbooks.md'
if (Test-Path -LiteralPath $playbookGuidePath) {
    $playbookGuideText = Get-Content -Raw -Encoding UTF8 -LiteralPath $playbookGuidePath
    $requiredPlaybookGuideRules = @(
        '`HypothesisProposal.vulnerability_type_candidates`',
        '`PlaybookPolicy`',
        '`PlaybookApplication`',
        '`template_key`',
        '`playbook_application_ref`',
        '가설 자체의 반증 질문',
        'application 질문'
    )
    foreach ($marker in $requiredPlaybookGuideRules) {
        if (-not $playbookGuideText.Contains($marker)) {
            Add-Failure "verification playbook guide is missing shared-contract marker: $marker"
        }
    }
}

# R4 owns the machine-readable policy collection, freshness and Gate 2 linkage
# contracts. These checks prevent narrative-only policy rules from drifting away
# from the common schema consumed by R5 and R8.
$policySourceCheckBlock = [regex]::Match($contractText, '(?ms)^PolicySourceCheck:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$policyParserResultBlock = [regex]::Match($contractText, '(?ms)^PolicyParserResult:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$policyCollectionResultBlock = [regex]::Match($contractText, '(?ms)^PolicyCollectionResult:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$policyMissingInfoBlock = [regex]::Match($contractText, '(?ms)^PolicyMissingInfo:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$ruleScopeEvidenceLinkBlock = [regex]::Match($contractText, '(?ms)^RuleScopeEvidenceLink:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$programPolicyRecordBlock = [regex]::Match($contractText, '(?ms)^ProgramPolicyRecord:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$ruleScopeImpactReviewBlock = [regex]::Match($contractText, '(?ms)^RuleScopeImpactReview:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$primitiveAdmissionDecisionBlock = [regex]::Match($contractText, '(?ms)^PrimitiveAdmissionDecision:\s*(.*?)(?=^[A-Za-z][A-Za-z0-9_]*:|\z)').Groups[1].Value
$gateRuleScopeImpactReviewBlock = [regex]::Match($gateText, '(?ms)^rule_scope_impact_review:\s*(.*?)^```').Groups[1].Value
$analysisRunResultPolicyBlock = [regex]::Match($contractText, '(?ms)^AnalysisRunResult:\s*(.*?)^```').Groups[1].Value

$requiredPolicyContractFields = @(
    @{ Contract = 'PolicySourceCheck'; Block = $policySourceCheckBlock; Fields = @('source_id: string', 'source_ref: StoredDataRef', 'status: VERIFIED | UNVERIFIED', 'evidence_refs: [StoredDataRef]', 'checked_at: timestamp') },
    @{ Contract = 'PolicyParserResult'; Block = $policyParserResultBlock; Fields = @('parser_result_id: string', 'parser_name: string', 'parser_version: string', 'source_ref: StoredDataRef', 'parsed_output_ref: StoredDataRef | null', 'status: SUCCEEDED | FAILED | INVALID_OUTPUT', 'error_ids: [string]', 'completed_at: timestamp') },
    @{ Contract = 'PolicyCollectionResult'; Block = $policyCollectionResultBlock; Fields = @('collection_result_id: string', 'program_id: string', 'status: FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED', 'official_source_refs: [StoredDataRef]', 'parser_result_refs: [StoredDataRef]', 'policy_record_ref: StoredDataRef | null', 'gap_ids: [string]', 'error_ids: [string]', 'completed_at: timestamp') },
    @{ Contract = 'PolicyMissingInfo'; Block = $policyMissingInfoBlock; Fields = @('missing_info_id: string', 'area: RULE | SCOPE | IMPACT | SOURCE | FRESHNESS | TESTING_RESTRICTION', 'blocks_allow: boolean', 'description: string', 'policy_item_ids: [string]', 'evidence_refs: [StoredDataRef]') },
    @{ Contract = 'RuleScopeEvidenceLink'; Block = $ruleScopeEvidenceLinkBlock; Fields = @('link_id: string', 'area: RULE | SCOPE | IMPACT | TESTING_RESTRICTION', 'policy_item_ids: [string]', 'evidence_refs: [StoredDataRef]') },
    @{ Contract = 'ProgramPolicyRecord'; Block = $programPolicyRecordBlock; Fields = @('source_checks: [PolicySourceCheck]', 'parser_result_refs: [StoredDataRef]', 'freshness_criterion_ref: StoredDataRef | null', 'freshness_evidence_refs: [StoredDataRef]', 'freshness_valid_until: timestamp | null', 'missing_information: [PolicyMissingInfo]') },
    @{ Contract = 'RuleScopeImpactReview'; Block = $ruleScopeImpactReviewBlock; Fields = @('policy_collection_result_ref: StoredDataRef', 'testing_restriction_compliance: PASS | FAIL | UNCERTAIN', 'evidence_links: [RuleScopeEvidenceLink]', 'missing_information: [PolicyMissingInfo]') }
    @{ Contract = 'PrimitiveAdmissionDecision'; Block = $primitiveAdmissionDecisionBlock; Fields = @('meta: RecordMeta', 'verification_result_ref: StoredDataRef', 'technical_review_ref: StoredDataRef', 'policy_collection_result_ref: StoredDataRef', 'rule_scope_review_ref: StoredDataRef | null', 'testing_restriction_compliance: PASS | FAIL | UNCERTAIN | NOT_EVALUATED', 'decision: ALLOW | DENY', 'reason_code: TESTING_RESTRICTION_PASSED | TESTING_RESTRICTION_UNCERTAIN | POLICY_COLLECTION_FAILED | TESTING_RESTRICTION_VIOLATION') }
    @{ Contract = 'Primitive'; Block = $primitiveBlock; Fields = @('admission_decision_ref: StoredDataRef | null') }
    @{ Contract = 'Gate guide RuleScopeImpactReview'; Block = $gateRuleScopeImpactReviewBlock; Fields = @('policy_collection_result_ref: StoredDataRef', 'evidence_links: [RuleScopeEvidenceLink]', 'missing_information: [PolicyMissingInfo]') }
    @{ Contract = 'AnalysisRunResult'; Block = $analysisRunResultPolicyBlock; Fields = @('policy_collection_result_refs: [StoredDataRef]', 'policy_parser_result_refs: [StoredDataRef]') }
)
foreach ($contract in $requiredPolicyContractFields) {
    if ([string]::IsNullOrWhiteSpace($contract.Block)) {
        Add-Failure "missing R4 policy contract block: $($contract.Contract)"
        continue
    }
    foreach ($field in $contract.Fields) {
        if (-not $contract.Block.Contains($field)) {
            Add-Failure "$($contract.Contract) is missing R4 policy field: $field"
        }
    }
}

$requiredPolicyContractRules = @(
    @{ Name = 'policy result owners are registered'; Text = $contractText; Marker = '`policy_parser_result -> PolicyParserResult -> POLICY_COLLECTOR`, `policy_collection_result -> PolicyCollectionResult -> POLICY_COLLECTOR`, `program_policy_record -> ProgramPolicyRecord -> POLICY_COLLECTOR`' },
    @{ Name = 'FOUND requires a policy record'; Text = $contractText; Marker = '`FOUND`이면 `policy_record_ref`가 필수이고 `error_ids=[]`다.' },
    @{ Name = 'successful collection uses successful parsers'; Text = $contractText; Marker = '`FOUND | ABSENT_CONFIRMED`의 `parser_result_refs`는 하나 이상이고 모두 `status=SUCCEEDED`인 exact parser 결과를 가리킨다.' },
    @{ Name = 'FOUND binds collection and policy provenance'; Text = $contractText; Marker = '`FOUND`에서는 collection의 `official_source_refs`, `parser_result_refs`가 정책 record의 `source_refs`, `parser_result_refs`와 각각 set-equal해야 한다.' },
    @{ Name = 'confirmed absence is not a fetch failure'; Text = $contractText; Marker = '`ABSENT_CONFIRMED`이면 `policy_record_ref=null`, 하나 이상의 공식 출처와 `gap_ids`가 필요하고 `error_ids=[]`다.' },
    @{ Name = 'collection failure cannot produce a Gate review'; Text = $contractText; Marker = '`COLLECTION_FAILED`이면 `policy_record_ref=null`과 하나 이상의 `error_ids`가 필요하며 Rule Scope Gate work와 review를 만들지 않는다.' },
    @{ Name = 'Gate input includes the exact collection result'; Text = $contractText; Marker = '`policy_collection_result_ref`는 Gate가 사용한 exact `PolicyCollectionResult`를 가리킨다.' },
    @{ Name = 'CURRENT policy has enforceable freshness'; Text = $contractText; Marker = '`freshness_status=CURRENT`이면 `freshness_criterion_ref`, 하나 이상의 `freshness_evidence_refs`, `freshness_checked_at`과 미래의 `freshness_valid_until`이 모두 필수다.' },
    @{ Name = 'R8 owns freshness criteria'; Text = $contractText; Marker = 'freshness 기준값과 재수집 주기는 R8이 승인한 versioned 설정만 사용한다.' },
    @{ Name = 'Gate guide keeps R8 freshness ownership'; Text = $gateText; Marker = '최신성 기준값과 재수집 주기는 R8이 승인한 versioned 설정을 사용하고 R5는 그 결과를 정책 의미로 해석한다.' },
    @{ Name = 'Gate Wiki distinguishes collection failure'; Text = $gateWikiText; Marker = '`COLLECTION_FAILED`는 Rule Scope review를 만들지 않습니다.' },
    @{ Name = 'Gate diagram routes collection failure through admission runtime'; Text = $diagramText; Marker = 'COLLECT -->|COLLECTION_FAILED| ARUN[R4 Primitive Admission Runtime]' },
    @{ Name = 'Gate evidence links are complete'; Text = $contractText; Marker = '`PASS | FAIL | SUFFICIENT | INSUFFICIENT`인 각 판단 영역은 같은 area의 `RuleScopeEvidenceLink`를 하나 이상 가져야 한다.' },
    @{ Name = 'blocking missing information denies ALLOW'; Text = $contractText; Marker = '`blocks_allow=true`인 `PolicyMissingInfo`가 하나라도 있으면 `report_permission=ALLOW`를 저장하지 않는다.' },
    @{ Name = 'policy fetch error does not become a successful Gate result'; Text = $resultText; Marker = '`POLICY_FETCH_ERROR` | 정책 수집 계층 | 정책 수집 결과 `COLLECTION_FAILED`; 성공한 Rule Scope review 없음' },
    @{ Name = 'policy parser error is distinct'; Text = $resultText; Marker = '`POLICY_PARSE_ERROR` | 정책 수집 계층 | parser 실행 실패와 `COLLECTION_FAILED`; 성공한 Rule Scope review 없음' },
    @{ Name = 'policy collection negative scenario exists'; Text = $securityText; Marker = '| N35 | 정책 수집 실패를 정책 부재로 바꿔 `UNCERTAIN + DENY` review를 저장 |' },
    @{ Name = 'policy evidence negative scenario exists'; Text = $securityText; Marker = '| N36 | Rule·Scope·Impact 확정 판단에 사용한 정책 항목 또는 실제 근거 연결이 없음 |' },
    @{ Name = 'primitive admission decision owner is registered'; Text = $contractText; Marker = '`primitive_admission_decision -> PrimitiveAdmissionDecision -> PRIMITIVE_ADMISSION_RUNTIME`' },
    @{ Name = 'TRUE primitive binds admission decision'; Text = $contractText; Marker = '`result`가 있는 Primitive의 `admission_decision_ref`는 같은 Verification의 current `PrimitiveAdmissionDecision(decision=ALLOW)`을 exact하게 가리켜야 한다.' },
    @{ Name = 'testing restriction verdict is independent'; Text = $contractText; Marker = '`testing_restriction_compliance`는 `rule_compliance`와 독립된 판정 축이다.' },
    @{ Name = 'confirmed prohibited testing denies admission'; Text = $contractText; Marker = '`testing_restriction_compliance=FAIL`이면 `decision=DENY`, `reason_code=TESTING_RESTRICTION_VIOLATION`만 허용하고 result Primitive를 만들지 않는다.' },
    @{ Name = 'policy collection failure keeps exact provenance'; Text = $contractText; Marker = '`COLLECTION_FAILED`이면 `rule_scope_review_ref=null`, `testing_restriction_compliance=NOT_EVALUATED`, `decision=ALLOW`, `reason_code=POLICY_COLLECTION_FAILED`로만 확정한다.' },
    @{ Name = 'chaining registration pins direct and ancestor allowed decisions'; Text = $contractText; Marker = '이들에 직접·재귀적으로 연결된 current ALLOW decision exact reference를 함께 고정한다.' },
    @{ Name = 'stale used admission blocks in-flight chaining'; Text = $contractText; Marker = '`source_admission_refs` 중 하나가 current가 아니거나 `DENY`로 바뀌면 오염된 재료의 사용을 막기 위해 진행 중인 결과를 거절한다.' },
    @{ Name = 'derived hypothesis rechecks admission lineage'; Text = $contractText; Marker = '`origin=CHAINING` 가설의 새 Verification·Gate·Primitive update·Reporter work를 등록하거나 그 결과를 저장할 때도 trusted runtime은 같은 `source_primitive_match_id` 계보의 result Primitive admission decision을 재귀 확인한다.' },
    @{ Name = 'committed descendants become audit only after denial'; Text = $contractText; Marker = '이미 COMMITTED된 Verification·Gate·Finding·ReportDraft는 감사 이력으로 남기되 current 결과나 외부 전달 가능 결과로 사용하지 않는다.' },
    @{ Name = 'current run result excludes denied admission descendants'; Text = $contractText; Marker = '`ChainingResult.source_admission_refs` 중 하나라도 더 이상 current ALLOW가 아니면 해당 ChainingResult와 그 `source_primitive_match_id`에서 파생된 Primitive·Finding·ReportDraft를 current 목록에 넣지 않는다.' },
    @{ Name = 'report requires testing restriction pass'; Text = $contractText; Marker = 'testing_restriction_compliance PASS + scope_compliance PASS' },
    @{ Name = 'unrelated rule failure scenario exists'; Text = $securityText; Marker = '| N37 | 다른 규칙 때문에 `rule_compliance=FAIL`이지만 `testing_restriction_compliance=PASS` |' },
    @{ Name = 'prohibited testing scenario exists'; Text = $securityText; Marker = '| N38 | `testing_restriction_compliance=FAIL`인 Rule Scope review |' },
    @{ Name = 'ambiguous testing evidence scenario exists'; Text = $securityText; Marker = '| N39 | `TESTING_RESTRICTION` link만 있고 전용 판정이 없거나 판정과 link가 모순됨 |' },
    @{ Name = 'collection failure admission scenario exists'; Text = $securityText; Marker = '| N40 | 정책 수집이 `COLLECTION_FAILED`라 Rule Scope review가 없음 |' },
    @{ Name = 'stale admission decision scenario exists'; Text = $securityText; Marker = '| N41 | Chaining work가 실제 match에 사용한 admission decision 뒤 current decision이 `DENY`로 변경됨 |' },
    @{ Name = 'missing admission reference scenario exists'; Text = $securityText; Marker = '| N42 | result Primitive에 current `admission_decision_ref`가 없거나 다른 Verification의 decision을 참조 |' },
    @{ Name = 'committed descendant invalidation scenario exists'; Text = $securityText; Marker = '| N43 | 이미 COMMITTED된 Chaining 자식·손자 뒤 부모 admission이 `DENY`로 변경됨 |' },
    @{ Name = 'source admission set mismatch scenario exists'; Text = $securityText; Marker = '| N44 | `ChainingResult.source_admission_refs`가 실제 match의 direct·ancestor ALLOW decision 합집합과 다름 |' },
    @{ Name = 'Wiki explains collection outcomes'; Text = $commonWikiText; Marker = '`FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`' },
    @{ Name = 'Wiki explains primitive admission decision'; Text = $commonWikiText; Marker = '`PrimitiveAdmissionDecision`은 TRUE 결과를 체이닝 재료로 사용해도 되는지 기록합니다.' },
    @{ Name = 'authority Wiki separates policy meaning and runtime derivation'; Text = $authorityWikiText; Marker = 'Rule Scope Gate가 테스트 제한의 의미를 판단하고, Runtime은 그 구조화된 판정으로 `PrimitiveAdmissionDecision`을 확정합니다.' },
    @{ Name = 'overview requires admission ALLOW for result Primitive'; Text = $overviewText; Marker = 'current admission `ALLOW`인 Technical-accepted TRUE의 result Primitive exact revision 검색' },
    @{ Name = 'orchestration fixes primitive admission order'; Text = $orchestrationText; Marker = '-> PrimitiveAdmissionDecision' },
    @{ Name = 'architecture hub explains confirmed prohibited testing denial'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/README.md')); Marker = '금지 테스트 위반이 확정된 `DENY`는 result Primitive와 Chaining을 막지만' },
    @{ Name = 'canonical diagram routes Technical ACCEPT through admission'; Text = $diagramText; Marker = 'ADEC{PrimitiveAdmissionDecision}' },
    @{ Name = 'pipeline Wiki requires current admission ALLOW'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/pipeline.md')); Marker = 'TRUE는 Technical `ACCEPT`와 current admission `ALLOW` 뒤 들어간다.' },
    @{ Name = 'Chaining Wiki pins current ALLOW decision lineage'; Text = $chainingWikiText; Marker = '실제 입력의 direct·ancestor admission 집합은 `source_admission_refs`에 중복 없이 기록합니다.' },
    @{ Name = 'Gate Wiki separates testing restriction result'; Text = $gateWikiText; Marker = 'testing_restriction_compliance: `PASS | FAIL | UNCERTAIN`' },
    @{ Name = 'ownership assigns R1 current admission consumption'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/governance/OWNERSHIP.md')); Marker = 'R1 Chaining은 result Primitive와 직접·부모 체인의 current `PrimitiveAdmissionDecision=ALLOW`를 함께 입력으로 고정' },
    @{ Name = 'AnalysisRunResult policy refs use a new major'; Text = $contractText; Marker = '두 목록 추가는 `AnalysisRunResult`의 새 필수 필드이므로 새 MAJOR schema에서만 사용한다.' }
)
foreach ($rule in $requiredPolicyContractRules) {
    if (-not $rule.Text.Contains($rule.Marker)) {
        Add-Failure "missing R4 policy contract rule: $($rule.Name)"
    }
}

$primitiveAdmissionDecisionPath = Join-Path $repoRoot 'docs/review/decisions/ADR-011-testing-restriction-primitive-admission.md'
if (-not (Test-Path -LiteralPath $primitiveAdmissionDecisionPath)) {
    Add-Failure 'missing ADR-011 testing restriction primitive admission decision'
} else {
    $primitiveAdmissionDecisionText = Get-Content -Raw -Encoding UTF8 -LiteralPath $primitiveAdmissionDecisionPath
    foreach ($marker in @('상태: `ACCEPTED`', '`testing_restriction_compliance`', '`PrimitiveAdmissionDecision`', '`PRIMITIVE_ADMISSION_RUNTIME`', '`COLLECTION_FAILED`', 'R1:', 'R4:', 'R5-02:')) {
        if (-not $primitiveAdmissionDecisionText.Contains($marker)) {
            Add-Failure "ADR-011 is missing decision marker: $marker"
        }
    }
}
$policyDecisionIndexText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/decisions/README.md')
if (-not $policyDecisionIndexText.Contains('[ADR-011](./ADR-011-testing-restriction-primitive-admission.md)')) {
    Add-Failure 'decision index is missing ADR-011'
}

$dynamicLifecycleDocuments = @(
    @{ Name = '08 common contract'; Text = $contractText },
    @{ Name = '13 canonical diagrams'; Text = $diagramText },
    @{ Name = 'Wiki diagrams'; Text = $wikiDiagramText },
    @{ Name = 'verification Wiki'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/architecture-v5/wiki/verification-and-dynamic.md')) },
    @{ Name = 'OWNERSHIP'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/governance/OWNERSHIP.md')) },
    @{ Name = 'ISSUE_CATALOG'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/ISSUE_CATALOG.md')) }
)
foreach ($doc in $dynamicLifecycleDocuments) {
    foreach ($marker in @('같은 R7 Agent session', 'trigger=RETRY', 'trigger=RESUME')) {
        if (-not $doc.Text.Contains($marker)) {
            Add-Failure "$($doc.Name) is missing dynamic lifecycle distinction: $marker"
        }
    }
}
foreach ($legacy in @('RUNNING --> READY: immediate dynamic auto retry', '외부 대기 없는 새 attempt', 'Autonomous retry same work new attempt')) {
    if ($diagramText.Contains($legacy) -or $wikiDiagramText.Contains($legacy) -or $contractText.Contains($legacy)) {
        Add-Failure "obsolete dynamic retry marker remains: $legacy"
    }
}

$exactPlanDocuments = @(
    @{ Name = '01 overview'; Text = $overviewText },
    @{ Name = '03 orchestration'; Text = $orchestrationText },
    @{ Name = '10 security'; Text = $securityText },
    @{ Name = '13 diagrams'; Text = $diagramText },
    @{ Name = 'Wiki common contracts'; Text = $commonWikiText },
    @{ Name = 'ISSUE_CATALOG'; Text = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/review/ISSUE_CATALOG.md')) }
)
foreach ($doc in $exactPlanDocuments) {
    if (-not $doc.Text.Contains('current exact plan') -and -not $doc.Text.Contains('current exact `ReproductionPlan`')) {
        Add-Failure "$($doc.Name) is missing current exact ReproductionPlan binding"
    }
}
foreach ($marker in @('`SandboxProfile`', '`data_kind=sandbox_profile`', '`DynamicReproductionLifecycleProfile`', '`data_kind=dynamic_reproduction_lifecycle_profile`', '`ActionRequest.sandbox_profile_ref`', '`ActionRequest.resource_profile_ref`', '`ActionDecision.checked_config_refs`', '`SandboxPolicyDecision.sandbox_profile_ref`', '`SandboxPolicyDecision.resource_profile_ref`')) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing R8 resource/lifecycle profile reference contract: $marker"
    }
}
$glossaryText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repoRoot 'docs/GLOSSARY.md')
if (-not $glossaryText.Contains('R7이 소유·확정') -or -not $glossaryText.Contains('CPU·RAM·disk·PID·요청 가능 최대 시간') -or -not $glossaryText.Contains('호출 전 work 잔여 시간 검사 정책과 새 attempt 한도') -or -not $glossaryText.Contains('CPU·RAM·disk·PID·요청 가능 최대 시간은 포함하지 않습니다.')) {
    Add-Failure 'glossary does not separate sandbox_profile_ref from the R8 resource/lifecycle profile'
}
foreach ($marker in @('SandboxCommandRecord:', 'command_ref: StoredDataRef | null', 'command_digest: string | null', '`sandbox_command_record -> SandboxCommandRecord -> REPRODUCTION_SESSION_MANAGER`')) {
    if (-not $contractText.Contains($marker)) {
        Add-Failure "missing AgentLog command trace contract: $marker"
    }
}
if (-not $securityText.Contains('`COMMAND_STARTED`와 `COMMAND_FINISHED`의 command ref·digest·action·attempt·environment가 다르거나 redaction이 유효하지 않음')) {
    Add-Failure 'security scenarios are missing command trace rejection'
}
# R7/R8 sandbox admission and lifecycle ownership must remain distinct.
$resultContractText = Get-Content -Raw -Encoding UTF8 (Join-Path $repoRoot 'docs/architecture-v5/07-results-and-observability.md')
$resultContractMarkers = @(
    '초안은 새 attempt 4회(최초 1회 별도, 총 5회)',
    '실행 **요청 전** 잔여 시간이 없으면 `BUDGET_EXCEEDED`',
    '상자 시간이 R7 `sandbox_profile_ref`의 입장 상한(아래 표)보다 김 → Sandbox Controller `SANDBOX_POLICY_DENIED`',
    'Agent가 실행 중 시계가 끝남 → `FAILED + TIMEOUT`',
    '구체 수치는 R7이 확정한다'
)
foreach ($marker in $resultContractMarkers) {
    if (-not $resultContractText.Contains($marker)) {
        Add-Failure "missing R7/R8 sandbox admission marker in 07: $marker"
    }
}

$activeArchitectureText = $activeDocumentationText

$forbiddenR8OwnershipMarkers = @(
    '그 R8 profile의 수치',
    'R8 profile의 CPU',
    'R8이 CPU·RAM·디스크·PID 값을 확정',
    'R8이 CPU·RAM·disk·PID 값을 확정'
)
foreach ($marker in $forbiddenR8OwnershipMarkers) {
    if ($activeArchitectureText.Contains($marker)) {
        Add-Failure "R8 must not own R7 sandbox admission limits: $marker"
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
Write-Output 'Finding lifecycle Rule Scope -> FINDING_NORMALIZE bypass guard: canonical + Wiki'
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
Write-Output "R8 common contract rules: $($requiredR8CommonContractRules.Count)"
Write-Output 'R5-03 ReportDraft safety fields: 7'
Write-Output 'R4-03 exact LLM call blocks: 2'
Write-Output "R4-03 authority errors: $($requiredAuthorityErrors.Count)"
Write-Output "R4-03 authority scenarios: $($authorityScenarioMarkers.Count)"
Write-Output "R4-03 authority rules: $($requiredAuthorityRules.Count)"
Write-Output "R5-01 CWELabel cross-document rules: $($requiredCweLabelCrossDocumentRules.Count)"
Write-Output "Playbook application contract blocks: $($requiredPlaybookContractFields.Count)"
Write-Output "Playbook application contract rules: $($requiredPlaybookApplicationRules.Count)"
Write-Output "Playbook application cross-document rules: $($requiredPlaybookCrossDocumentRules.Count)"
if (Test-Path -LiteralPath $playbookGuidePath) {
    Write-Output "Verification playbook guide rules: $($requiredPlaybookGuideRules.Count)"
}
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
Write-Output "Static layer Primitive admission rules: $($requiredStaticPrimitiveAdmissionRules.Count)"
Write-Output "R4 policy contract blocks: $($requiredPolicyContractFields.Count)"
Write-Output "R4 policy contract rules: $($requiredPolicyContractRules.Count)"
Write-Output "Failures: $($failures.Count)"

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Architecture document validation passed.'
