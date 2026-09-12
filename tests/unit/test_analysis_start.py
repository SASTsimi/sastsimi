import pytest

from sastsimi.contracts.ids import ProgramId


@pytest.mark.parametrize("matches", [(), ("program", "program"), ("other",)])
def test_start_rejects_unresolved_or_ambiguous_program(
    matches: tuple[str, ...],
) -> None:
    from sastsimi.runtime.analysis_start import AnalysisStartService

    class Resolver:
        def resolve(self, program_id: ProgramId) -> tuple[ProgramId, ...]:
            return tuple(ProgramId(value) for value in matches)

    with pytest.raises(ValueError, match="INPUT_ERROR"):
        AnalysisStartService(Resolver()).validate(
            repository_ref="fixture-repository",
            requested_git_ref="a" * 40,
            program_id="program",
            purpose="PRODUCTION",
        )


def test_start_preserves_explicit_single_program_and_git_ref() -> None:
    from sastsimi.runtime.analysis_start import AnalysisStartService

    class Resolver:
        def resolve(self, program_id: ProgramId) -> tuple[ProgramId, ...]:
            return (program_id,)

    request = AnalysisStartService(Resolver()).validate(
        repository_ref="fixture-repository",
        requested_git_ref="A" * 40,
        program_id="program",
        purpose="PRODUCTION",
    )
    assert request.model_dump(mode="json") == dict(
        repository_ref="fixture-repository",
        requested_git_ref="a" * 40,
        program_id="program",
        purpose="PRODUCTION",
    )


@pytest.mark.parametrize("commit", ["main", "", "g" * 40, "a" * 39, "a" * 65])
def test_start_rejects_non_exact_commit(commit: str) -> None:
    from sastsimi.runtime.analysis_start import AnalysisStartService

    class Resolver:
        def resolve(self, program_id: ProgramId) -> tuple[ProgramId, ...]:
            return (program_id,)

    with pytest.raises(ValueError, match="INPUT_ERROR"):
        AnalysisStartService(Resolver()).validate(
            repository_ref="fixture-repository",
            requested_git_ref=commit,
            program_id="program",
            purpose="PRODUCTION",
        )
