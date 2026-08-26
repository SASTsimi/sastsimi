# Architecture v5 가져오기 출처

## 중요 고지

이 candidate baseline은 소스 저장소의 **커밋되지 않은 working tree**에서 2026-08-27(Asia/Seoul)에 가져왔다. 따라서 아래 branch와 HEAD는 당시 작업 위치를 설명할 뿐, 이 파일들이 해당 commit에 포함되었다는 뜻이 아니다.

| 항목 | 값 |
|---|---|
| source working tree | `ai-sast-bugbounty` 로컬 작업 트리 |
| source branch | `agent/issue-25-discovery-v02-architecture` |
| source HEAD at capture | `79b2591674ac33db9d3677226957a8f897add3c5` |
| source path | `docs/architecture-v5/` |
| source Git state | 전체 `docs/architecture-v5/`가 untracked, source root `README.md` modified |
| target repository | `SASTsimi/sastsimi` |
| target path | `docs/architecture-v5/` |
| capture date | `2026-08-27` Asia/Seoul |

원본 root `README.md`, 원본 `docs/README.md`, 구현 코드, 테스트 결과와 v3/v4 bundle은 가져오지 않았다. 이 저장소용 root README와 governance 문서는 별도로 작성했다. Wiki는 사용자 요구에 따라 가져왔지만 파생·비규범적 문서로 명시했다.

## 원본 파일 SHA-256 manifest

아래 해시는 가져오기 직전 소스 working tree 파일의 값이다. 이 브랜치에서 수행한 review-context 수정 후의 해시가 아니다.

| 원본 상대 경로 | SHA-256 |
|---|---|
| `01-system-overview.md` | `533dc88cbc8c5071de8f5a9715037f148c701c0d78d7a7ae3c7c59ba96585c5b` |
| `02-static-fact-layer.md` | `7526b16aa6d9c482e0bea27943b385a06844f4715cb2b4eb8cd0973a751d25ee` |
| `03-agent-roles-and-orchestration.md` | `1325f7f7bdad2c16301213cb5d805f389afe87cd31e310fd5954c0d849c354f3` |
| `04-verification-and-dynamic-reproduction.md` | `d0a4e398d3006b806f3f21cb07950024b53b97e14578e16d780a11d105500bc3` |
| `05-llm-gate-and-reporting.md` | `9ed7d3ae69ada09b4abdc0b03855e5fe998e25cfc0b4e272c44c2e5ed2a9c843` |
| `06-chaining.md` | `7f8777eead63ff350391c3da13b3a7eff473982e8956149ada363edb0d7df2b6` |
| `07-results-and-observability.md` | `2845de0dd0b7bc4fb172f297522a3c5995ce844eabda9afc198c44d6c7e097f4` |
| `08-lightweight-data-contracts.md` | `d4c5ab2f4005647cc703938036185bc50f016ec56909be3ee7fa54533a2b5f90` |
| `09-llm-provider-session-and-logging.md` | `5019a680e96523937ca6dd241a14960290bd466f241c555fd10dbe10fab12fe4` |
| `10-security-boundaries.md` | `12e8491ed34d2216d2496e97501557d2c637215fbb2aec3fc8f91a20f0414d37` |
| `11-migration-from-v4.md` | `87d878e02bc28d3b0d3338822a8437f8d8f829354d8bc6df08341430a0cbfcf3` |
| `12-report-draft-template.md` | `8feab757ad9aeaa5ea32226773a6785c60a6b89ad950f735ca9c78c6efbe036c` |
| `13-architecture-diagrams.md` | `eb3c2c336e956cd454b144872c86c160cc44546d6f4e1d1a617870a1b3118a85` |
| `README.md` | `01b4d28806eee3d773b425bc5b49376b262d2ad748b195f1dd1c554bc50de2be` |
| `wiki/.nojekyll` | `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` |
| `wiki/_Sidebar.md` | `6b5ca76f98b0ed1a5a55f62ceffacc09da7c45c92d105eab60beb9c997ca92f0` |
| `wiki/agents.md` | `7a5d32d24a937b27e5a23763925ee383b0d1b7ac30af35f17a18889237b198d4` |
| `wiki/chaining.md` | `7795b61a91c749caa1841d0913b68023c3ec707d7ff014b4ba265709b3b440b8` |
| `wiki/diagrams.md` | `eb3c2c336e956cd454b144872c86c160cc44546d6f4e1d1a617870a1b3118a85` |
| `wiki/gate-and-reporting.md` | `9c894b7cd8baed3b11f277d76922e74bee92adc5a3d74680ecc1dfec5a196083` |
| `wiki/index.html` | `a494508e9b55d4cb6a44c3ea8e3729272bbdfd27c48a4d9792e009ee104e610e` |
| `wiki/pipeline.md` | `30cd024ef7841d95e246d0168b6f084789e776d0184d15c79422bd1ee6a84a1e` |
| `wiki/providers-and-logging.md` | `ff5870aa267cb4609edea3889e2c24ed354a963af865bf71bf0ef2fa61a4a217` |
| `wiki/quick-guide.md` | `42e352758ea3471d3db3eccdbd414ae6be77997f36270910ffaffd8fc601cc5d` |
| `wiki/README.md` | `f35022d095a4f7703b7fc376b9cdca5e4d1fee71f0f210032b07d6ff44a8e114` |
| `wiki/results.md` | `6d216bb8d9d0285b0683b01cce266c7096d2ba541b8944d1c7bd38edb617eeb4` |
| `wiki/serve.ps1` | `85157adf2ee092f8dfe55bf2184912675774740f90ee7937bc310bddc9f679c3` |
| `wiki/theme.css` | `a0f82e7895e78fd1f2920293bd956f9b9dd0bffa133f483f7e1c6591506f0781` |
| `wiki/verification-and-dynamic.md` | `d8d8a775172e3429c64c20c289915b6e1ca45a6e18eb56d849ab645cd5949363` |

## 변경과 동기화 규칙

1. 검토 결정은 이 저장소의 Issue와 PR에서 먼저 기록한다.
2. 승인 전 candidate를 구현 완료 또는 정본으로 부르지 않는다.
3. 검토 완료 시 freeze commit SHA와 승인 결과를 기록한다.
4. 구현 저장소 반영은 승인된 SHA를 출처로 하는 별도 PR에서 수행한다.
5. 어느 방향이든 파일을 조용히 복사하거나 양쪽에서 동시에 같은 계약을 편집하지 않는다.
