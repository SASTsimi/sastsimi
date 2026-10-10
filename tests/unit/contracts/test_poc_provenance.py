"""Conservative provenance checks for in-process PoC-only pickle fixtures."""

from __future__ import annotations

from sastsimi.contracts.poc_provenance import (
    PocProvenanceEvidence,
    PocProvenanceStatus,
    assess_poc_provenance,
)


def _script(python: str) -> bytes:
    return ("#!/bin/sh\npython3 -B - <<'PY'\n" + python + "\nPY\n").encode()


def test_local_class_pickled_into_same_process_client_is_unverified() -> None:
    content = _script(
        """import base64
import pickle
class LocalFixture:
    def __str__(self):
        return 'fixture_value'
client = app.test_client()
encoded = base64.b64encode(pickle.dumps(LocalFixture())).decode('ascii')
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    assert result.evidence is PocProvenanceEvidence.PROCESS_LOCAL_PICKLE_TEST_CLIENT
    assert "LocalFixture" not in repr(result)


def test_class_body_local_pickle_sent_via_test_client_is_unverified() -> None:
    content = _script(
        "import pickle\n"
        "class LocalFixture: pass\n"
        "class Payload:\n"
        "    token = pickle.dumps(LocalFixture())\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', Payload.token)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_class_alias_cannot_hide_class_body_local_pickle() -> None:
    content = _script(
        "import pickle\n"
        "class LocalFixture: pass\n"
        "class Payload:\n"
        "    token = pickle.dumps(LocalFixture())\n"
        "Alias = Payload\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', Alias.token)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_unrelated_class_body_local_pickle_does_not_block_literal_cookie() -> None:
    content = _script(
        "import pickle\n"
        "class LocalFixture: pass\n"
        "class Payload:\n"
        "    token = pickle.dumps(LocalFixture())\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', pickle.dumps('ordinary literal'))\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_overwritten_class_body_pickle_field_is_not_a_local_fixture() -> None:
    content = _script(
        "import pickle\n"
        "class LocalFixture: pass\n"
        "class Payload:\n"
        "    token = pickle.dumps(LocalFixture())\n"
        "Payload.token = pickle.dumps('ordinary literal')\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', Payload.token)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_indirect_test_client_access_cannot_clear_local_pickle_signal() -> None:
    for setup, expression in (
        ("", "getattr(app, 'test_client')()"),
        ("", "getattr(app, 'test' + '_client')()"),
        ("", "app.__getattribute__('test_client')()"),
        ("client_factory = getattr\n", "client_factory(app, 'test_client')()"),
    ):
        content = _script(
            "import pickle\n"
            "class LocalFixture: pass\n"
            f"{setup}"
            f"client = {expression}\n"
            "payload = pickle.dumps(LocalFixture())\n"
            "client.set_cookie('value', payload)\n"
            "client.get('/cookie')"
        )

        assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_indirect_attribute_access_does_not_reject_literal_pickle_value() -> None:
    content = _script(
        "import pickle\n"
        "class LocalFixture: pass\n"
        "client = getattr(app, 'test_client')()\n"
        "payload = pickle.dumps('safe literal')\n"
        "client.set_cookie('value', payload)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_local_class_constructor_alias_cannot_pass_same_process_client() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
Alias = LocalFixture
client = app.test_client()
encoded = pickle.dumps(Alias())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_dynamically_created_local_class_is_not_independent_proof() -> None:
    for setup, expression in (
        ("", "type('Payload', (), {})"),
        ("import types\n", "types.new_class('Payload')"),
        (
            "from dataclasses import make_dataclass\n",
            "make_dataclass('Payload', [])",
        ),
    ):
        content = _script(
            "import pickle\n"
            f"{setup}"
            f"Payload = {expression}\n"
            "client = app.test_client()\n"
            "encoded = pickle.dumps(Payload())\n"
            "client.set_cookie('value', encoded)\n"
            "client.get('/cookie')"
        )

        assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_opaque_factory_and_nested_dynamic_class_need_independent_proof() -> None:
    for creation in (
        "factory = load_class_factory()\nPayload = factory('Payload')\n"
        "encoded = pickle.dumps(Payload())\n",
        "encoded = pickle.dumps(type('Payload', (), {})())\n",
    ):
        content = _script(
            "import pickle\n"
            "client = app.test_client()\n"
            + creation
            + "client.set_cookie('value', encoded)\n"
            "client.get('/cookie')"
        )

        assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_poc_local_factory_return_and_dynamic_class_object_are_unresolved() -> None:
    for creation in (
        "def fixture():\n    return type('Payload', (), {})()\n"
        "encoded = pickle.dumps(fixture())\n",
        "encoded = pickle.dumps(type('Payload', (), {}))\n",
    ):
        content = _script(
            "import pickle\n"
            "client = app.test_client()\n"
            + creation
            + "client.set_cookie('value', encoded)\n"
            "client.get('/cookie')"
        )

        assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_importable_builtin_eval_with_literal_arguments_is_not_local_fixture() -> None:
    content = _script(
        "import builtins\n"
        "import pickle\n"
        "client = app.test_client()\n"
        "encoded = pickle.dumps((builtins.eval, ('40 + 2',)))\n"
        "client.set_cookie('value', encoded)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_pickle_dumps_alias_cannot_hide_local_fixture() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
dump = pickle.dumps
client = app.test_client()
encoded = dump(LocalFixture())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_literal_importlib_pickle_module_alias_cannot_hide_local_fixture() -> None:
    content = _script(
        "import importlib as loader\n"
        "module = loader.import_module('pickle')\n"
        "serializer = module\n"
        "class LocalFixture: pass\n"
        "encoded = serializer.dumps(LocalFixture())\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', encoded)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_literal_import_module_function_alias_cannot_hide_local_fixture() -> None:
    content = _script(
        "from importlib import import_module as load_module\n"
        "serializer = load_module('pickle')\n"
        "class LocalFixture: pass\n"
        "encoded = serializer.dumps(LocalFixture())\n"
        "client = app.test_client()\n"
        "client.set_cookie('value', encoded)\n"
        "client.get('/cookie')"
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_global_constructor_alias_used_in_function_is_not_independent() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
Alias = LocalFixture
def reproduce():
    client = app.test_client()
    encoded = pickle.dumps(Alias())
    client.set_cookie('value', encoded)
    client.get('/cookie')
reproduce()"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_global_dumps_alias_used_in_function_is_not_independent() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
dump = pickle.dumps
def reproduce():
    client = app.test_client()
    encoded = dump(LocalFixture())
    client.set_cookie('value', encoded)
    client.get('/cookie')
reproduce()"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_dynamic_constructor_alias_is_unknown_not_independent() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
registry = {'fixture': LocalFixture}
factory = registry['fixture']
client = app.test_client()
encoded = pickle.dumps(factory())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_local_serializer_class_with_builtin_eval_needs_external_proof() -> None:
    """Same-process test_client cannot prove an eval reducer independently."""

    content = _script(
        """import base64
import pickle
class Payload:
    def __reduce__(self):
        return (eval, ('40 + 2',))
client = app.test_client()
encoded = base64.b64encode(pickle.dumps(Payload(), protocol=4)).decode('ascii')
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE


def test_eval_reducer_with_dynamic_expression_is_not_proven_portable() -> None:
    content = _script(
        """import pickle
class Payload:
    def __reduce__(self):
        expression = '__import__("pathlib").Path(' + repr(marker) + ').write_text("x")'
        return (eval, (expression,))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_eval_reducer_referencing_poc_only_class_is_not_portable() -> None:
    content = _script(
        """import pickle
class LocalOnly:
    pass
class Payload:
    def __reduce__(self):
        return (eval, ("__import__('__main__').LocalOnly()",))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE


def test_eval_reducer_with_static_stdlib_import_needs_external_proof() -> None:
    content = _script(
        """import pickle
class Payload:
    def __reduce__(self):
        return (eval, ('__import__("pathlib").Path("/tmp/marker").name',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_eval_reducer_must_not_trust_poc_process_environment() -> None:
    content = _script(
        """import os
import pickle
os.environ['LOCAL_ONLY'] = 'fixture_value'
class Payload:
    def __reduce__(self):
        return (eval, ("__import__('os').environ.get('LOCAL_ONLY')",))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_local_serializer_class_with_imported_os_system_reducer_is_portable() -> None:
    """The pickle calls an importable standard-library global, not Payload."""

    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload(), protocol=4)
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    assert result.evidence is PocProvenanceEvidence.NONE


def test_local_serializer_class_with_aliased_os_system_reducer_is_portable() -> None:
    content = _script(
        """import os as standard_os
import pickle
class Payload:
    def __reduce__(self):
        return (standard_os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_rebound_portable_reduce_method_cannot_pass_same_process_client() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
def poc_helper():
    return 'local-only'
def replacement(self):
    return (poc_helper, ())
Payload.__reduce__ = replacement
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_added_reduce_ex_method_cannot_pass_same_process_client() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
def poc_helper():
    return 'local-only'
def replacement(self, protocol):
    return (poc_helper, ())
Payload.__reduce_ex__ = replacement
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_rebound_reduce_through_class_alias_cannot_pass_same_process_client() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
Alias = Payload
def replacement(self):
    return (local_helper, ())
Alias.__reduce__ = replacement
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_setattr_reduce_rebinding_cannot_pass_same_process_client() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
def replacement(self):
    return (local_helper, ())
setattr(Payload, '__reduce__', replacement)
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_rebound_os_name_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
os = local_namespace
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_rebound_os_system_attribute_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
os.system = local_helper
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_setattr_rebinding_os_system_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
setattr(os, 'system', local_helper)
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_os_dict_rebinding_system_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
os.__dict__['system'] = local_helper
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_os_dict_update_cannot_rebind_portable_reducer() -> None:
    content = _script(
        """import os
import pickle
def local_helper(command):
    return 'local-only'
os.__dict__.update({'system': local_helper})
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_vars_os_alias_cannot_rebind_portable_reducer() -> None:
    content = _script(
        """import os
import pickle
def local_helper(command):
    return 'local-only'
namespace = vars(os)
namespace['system'] = local_helper
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_getattr_os_dict_alias_cannot_rebind_portable_reducer() -> None:
    content = _script(
        """import os
import pickle
def local_helper(command):
    return 'local-only'
namespace = getattr(os, '__dict__')
namespace.update({'system': local_helper})
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_locally_imported_os_name_remains_process_local() -> None:
    content = _script(
        """import local_os as os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_second_import_shadowing_os_name_remains_process_local() -> None:
    content = _script(
        """import os
import local_os as os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_os_system_reducer_with_local_object_argument_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
class LocalArgument:
    pass
class Payload:
    def __reduce__(self):
        return (os.system, (LocalArgument(),))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_os_system_reducer_with_reduce_ex_override_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, ('echo marker',))
    def __reduce_ex__(self, protocol):
        return (local_helper, ('echo marker',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_os_system_reducer_with_nonliteral_argument_remains_process_local() -> None:
    content = _script(
        """import os
import pickle
class Payload:
    def __reduce__(self):
        return (os.system, (command_from_local_helper(),))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_local_reducer_calling_poc_only_helper_remains_unverified() -> None:
    content = _script(
        """import pickle
def local_helper(value):
    return value
class Payload:
    def __reduce__(self):
        return (local_helper, ('fixture_value',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_shadowed_eval_reducer_remains_unverified() -> None:
    content = _script(
        """import pickle
def eval(value):
    return value
class Payload:
    def __reduce__(self):
        return (eval, ('40 + 2',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_builtin_eval_reducer_with_local_object_argument_remains_unverified() -> None:
    content = _script(
        """import pickle
class LocalArgument:
    pass
class Payload:
    def __reduce__(self):
        return (eval, (LocalArgument(),))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_custom_reduce_ex_cannot_be_bypassed_by_portable_reduce() -> None:
    content = _script(
        """import pickle
def local_helper(value):
    return value
class Payload:
    def __reduce__(self):
        return (eval, ('40 + 2',))
    def __reduce_ex__(self, protocol):
        return (local_helper, ('fixture_value',))
client = app.test_client()
encoded = pickle.dumps(Payload())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_local_instance_alias_and_pickle_import_alias_are_detected() -> None:
    content = _script(
        """from pickle import dumps as serialize
class LocalFixture:
    pass
fixture = LocalFixture()
packed = serialize(fixture)
cookie_value = packed.hex()
client = app.test_client()
client.set_cookie('value', cookie_value)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_local_pickle_fixture_sent_as_keyword_cookie_value_is_unverified() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
encoded = pickle.dumps(LocalFixture())
client = app.test_client()
client.set_cookie('value', value=encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_context_managed_test_client_cannot_validate_poc_only_pickle() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
payload = pickle.dumps(LocalFixture())
with app.test_client() as client:
    client.set_cookie('value', payload.hex())
    client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_overwritten_pickle_payload_is_not_proven_process_local_cookie() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
payload = pickle.dumps(LocalFixture())
payload = pickle.dumps('ordinary data')
client = app.test_client()
client.set_cookie('value', payload.hex())
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_overwritten_local_instance_is_not_a_pickled_local_fixture() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
fixture = LocalFixture()
fixture = 'ordinary data'
payload = pickle.dumps(fixture)
client = app.test_client()
client.set_cookie('value', payload.hex())
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_overwritten_test_client_is_not_proven_same_process_request() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
payload = pickle.dumps(LocalFixture())
client = app.test_client()
client = independent_client
client.set_cookie('value', payload.hex())
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_overwritten_cookie_client_is_not_proven_same_process_request() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
payload = pickle.dumps(LocalFixture())
client = app.test_client()
client.set_cookie('value', payload.hex())
client = independent_client
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_builtin_string_pickle_does_not_raise_local_fixture_signal() -> None:
    content = _script(
        """import pickle
payload = '<fixture-tag>fixture_value</fixture-tag>'
client = app.test_client()
encoded = pickle.dumps(payload)
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_string_from_local_class_is_not_a_pickled_local_instance() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    def __str__(self):
        return 'fixture_value'
client = app.test_client()
encoded = pickle.dumps(str(LocalFixture()))
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_shadowed_str_does_not_hide_a_pickled_local_instance() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
str = lambda value: value
client = app.test_client()
encoded = pickle.dumps(str(LocalFixture()))
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    )


def test_repository_imported_class_does_not_raise_local_fixture_signal() -> None:
    content = _script(
        """import pickle
from app.models import ExistingModel
client = app.test_client()
encoded = pickle.dumps(ExistingModel())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_unrelated_http_client_is_not_called_same_process_proof() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
encoded = pickle.dumps(LocalFixture())
requests.post('http://127.0.0.1/cookie', data=encoded)"""
    )

    assert (
        assess_poc_provenance(content).status
        is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def test_unresolved_client_alias_is_unknown_not_a_proven_local_fixture() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
encoded = pickle.dumps(LocalFixture())
client = app.test_client()
other.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNKNOWN
    assert result.evidence is PocProvenanceEvidence.RELEVANT_FLOW_UNRESOLVED


def test_length_of_pickle_is_not_treated_as_serialized_fixture() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
length = len(pickle.dumps(LocalFixture()))
client = app.test_client()
client.set_cookie('value', str(length))
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_wrapper_returning_client_is_unknown_not_proven_same_client() -> None:
    content = _script(
        """import pickle
class LocalFixture:
    pass
encoded = pickle.dumps(LocalFixture())
client = choose_client(app.test_client())
client.set_cookie('value', encoded)
client.get('/cookie')"""
    )

    assert assess_poc_provenance(content).status is PocProvenanceStatus.UNKNOWN


def test_relevant_unparseable_python_is_unknown_not_silent_pass() -> None:
    content = _script(
        """import pickle
client = app.test_client()
encoded = pickle.dumps(
client.set_cookie('value', encoded)"""
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNKNOWN
    assert result.evidence is PocProvenanceEvidence.PYTHON_AST_UNPARSEABLE


def test_unterminated_relevant_heredoc_is_unknown() -> None:
    content = (
        b"#!/bin/sh\npython3 - <<'PY'\nimport pickle\nclient = app.test_client()\n"
    )

    result = assess_poc_provenance(content)

    assert result.status is PocProvenanceStatus.UNKNOWN
    assert result.evidence is PocProvenanceEvidence.PYTHON_HEREDOC_INCOMPLETE


def test_plain_shell_without_pickle_path_has_no_signal() -> None:
    result = assess_poc_provenance(b"#!/bin/sh\nprintf 'observed\\n'\n")

    assert result.status is PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    assert result.evidence is PocProvenanceEvidence.NONE
