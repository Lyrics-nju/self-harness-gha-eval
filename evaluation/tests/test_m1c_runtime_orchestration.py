"""Offline fixtures only. No Docker, registry, build or task execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_identity as i
from scripts import m1c_runtime_orchestrator as o
from scripts import m1c_runtime_resources as r
from scripts import m1c_runtime_qualification as q
from scripts import m1c_runtime_builder_environment as e
from evaluation.tests import test_m1c_runtime_identity as fixtures


def observation():
    p = r.backend_policy()
    binding = json.loads((i.ROOT / 'configs/m1c_runtime_task_binding_v1.json').read_bytes())
    mounts = [{'target': '/installed-agent', 'type': 'bind', 'rw': False, 'source': '/fixture/program'},
              {'target': '/logs/artifacts', 'type': 'bind', 'rw': True, 'source': '/fixture/artifacts'}]
    return {'task_config_sha256': binding['task_config_sha256'], 'image_mapping': q.fixed_image(),
            'configured': binding['task_requested_resources'], 'backend': {
                'version': '0.21.0', 'sources': p['backend_sources'],
                'environment_tree_sha256': p['environment_tree_sha256'],
                'capabilities': {'cpu_limit': True, 'cpu_request': False, 'memory_limit': True, 'memory_request': False},
                'storage_quota_parameter': False},
            'resource_envelope': {'memory_bytes': 2048*1024**2, 'nano_cpus': 10**9, 'memory_swap': 4096*1024**2,
                'cpu_quota': 0, 'cpu_period': 0, 'cpuset_cpus': '', 'cpu_shares': 0, 'memory_reservation': 0,
                'pids_limit': None, 'storage_options': {}},
            'cgroup': {'version': 2, 'memory_max': 2048*1024**2, 'cpu_quota': 100000, 'cpu_period': 100000},
            'resource_overrides': [], 'network_mode': 'none',
            'storage_capability': 'NOT_ENFORCED_BY_CURRENT_BACKEND', 'storage_quota_verified': False,
            'mounts': mounts, 'expected_mounts': copy.deepcopy(mounts),
            'image_id': 'sha256:'+'a'*64, 'container_image_id': 'sha256:'+'a'*64}


class FixtureBackend:
    real = True  # Even a fixture claiming real cannot qualify.
    def __init__(self, fail=None, mutate=None):
        self.calls = []; self.fail = fail; self.mutate = mutate
        fixture = fixtures.IdentityTests(); fixture.setUp()
        self.image, self.capacity = fixture.image, fixture.resources
    def act(self, name):
        self.calls.append(name)
        if name == self.fail: raise a.ArtifactError('FIXTURE_FAILURE')
    def prepare(self): self.act('prepare')
    def create_builder(self): self.act('create_builder')
    def builder_identity(self): self.act('builder_identity'); return self.image
    def builder_capacity(self, image): self.act('builder_capacity'); return self.capacity
    def build_gate(self, image, resources): self.act('build_gate')
    def compile_dsh(self, image, resources): self.act('compile_dsh')
    def pack_and_verify(self): self.act('pack_and_verify')
    def create_task(self): self.act('create_task')
    def task_readback(self):
        self.act('task_readback'); result = observation()
        if self.mutate: self.mutate(result)
        return result
    def materialize(self, before): self.act('materialize')
    def native_probe(self, before): self.act('native_probe')
    def cleanup(self): self.act('cleanup')
    def capture_failure(self, error): self.act('capture_failure')
    def save_summary(self, summary): self.summary = summary


class OrchestrationTests(unittest.TestCase):
    def test_storage_gap_is_not_quota_pass(self):
        result = r.resource_gate(observation())
        self.assertEqual(result['storage']['configured_mb'], 10240)
        self.assertEqual(result['status'], 'TASK_RESOURCE_BASELINE_PRESERVED_WITH_STORAGE_GAP')
        self.assertEqual(result['storage']['enforcement_status'], 'NOT_ENFORCED_BY_CURRENT_BACKEND')
        self.assertFalse(result['storage']['hard_quota_verified'])
        self.assertFalse(result['all_resource_limits_enforced'])

    def test_each_resource_and_backend_drift_blocks(self):
        mutations = [('configured', 'storage_mb', 10241), ('configured', 'cpus', 2),
            ('configured', 'memory_mb', 1024), ('backend', 'version', '0.22.0'),
            ('backend', 'sources', {}), ('backend', 'environment_tree_sha256', '0'*64),
            ('backend', 'capabilities', {}), ('backend', 'storage_quota_parameter', True),
            ('resource_envelope', 'nano_cpus', 2*10**9), ('resource_envelope', 'memory_bytes', 0),
            ('resource_envelope', 'storage_options', {'size': '10G'}),
            ('cgroup', 'memory_max', 0), ('cgroup', 'cpu_quota', 200000),
            ('cgroup', 'version', 1)]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                obs = observation(); obs[section][key] = value
                with self.assertRaises(a.ArtifactError): r.resource_gate(obs)

    def test_storage_unknown_df_or_storageopt_never_proof(self):
        for status in ('UNKNOWN', 'ENFORCED', 'DF_VERIFIED', 'STORAGEOPT_VERIFIED'):
            with self.subTest(status=status):
                obs = observation(); obs['storage_capability'] = status; obs['df_free_bytes'] = 10240*1024**2
                with self.assertRaises(a.ArtifactError): r.resource_gate(obs)
        obs = observation(); obs['storage_quota_verified'] = True
        with self.assertRaises(a.ArtifactError): r.resource_gate(obs)

    def test_mount_override_image_network_fail_closed(self):
        for key, value in [('mounts', []), ('resource_overrides', ['_override_storage_mb']),
                           ('network_mode', 'bridge'), ('container_image_id', 'sha256:'+'b'*64)]:
            with self.subTest(key=key):
                obs = observation(); obs[key] = value
                with self.assertRaises(a.ArtifactError): r.resource_gate(obs)

    def test_post_readback_preserves_defaults(self):
        before = observation(); after = copy.deepcopy(before)
        r.preserved(before, after)
        after['resource_envelope']['memory_swap'] = 0
        with self.assertRaisesRegex(a.ArtifactError, 'BASELINE_DRIFT'): r.preserved(before, after)

    def test_cgroup_unlimited_or_missing_fails(self):
        self.assertEqual(r.parse_cgroup('memory.max=2147483648\ncpu.max=100000 100000')['memory_max'], 2147483648)
        for text in ('memory.max=max\ncpu.max=100000 100000', 'memory.max=2147483648\ncpu.max=max 100000', ''):
            with self.subTest(text=text), self.assertRaises((ValueError, KeyError)): r.parse_cgroup(text)

    def test_mock_full_chain_not_real_pass(self):
        backend = FixtureBackend(); result = o.orchestrate(backend)
        self.assertEqual(result['status'], 'MOCK_EXECUTION_ONLY')
        for first, later in [('builder_identity','compile_dsh'), ('build_gate','compile_dsh'),
                              ('pack_and_verify','create_task'), ('task_readback','materialize'), ('materialize','native_probe')]:
            self.assertLess(backend.calls.index(first), backend.calls.index(later))
        self.assertEqual(result['provider_requests'], 0)
        self.assertFalse(result['adapter_frozen']); self.assertFalse(result['universal_compatibility'])

    def test_all_failure_boundaries_stop_next_action(self):
        cases = [('prepare','create_builder',o.STAGES[0]), ('builder_identity','compile_dsh',o.STAGES[1]),
            ('builder_capacity','compile_dsh',o.STAGES[2]), ('build_gate','compile_dsh',o.STAGES[2]),
            ('compile_dsh','pack_and_verify',o.STAGES[3]), ('pack_and_verify','create_task',o.STAGES[4]),
            ('create_task','materialize',o.STAGES[5]), ('native_probe',None,o.STAGES[6])]
        for fail, unreachable, status in cases:
            with self.subTest(fail=fail):
                backend = FixtureBackend(fail); result = o.orchestrate(backend)
                self.assertEqual(result['status'], status)
                if unreachable: self.assertNotIn(unreachable, backend.calls)
                self.assertIn('cleanup', backend.calls)

    def test_bad_image_capacity_no_build(self):
        for key in ('image', 'capacity'):
            backend = FixtureBackend()
            if key == 'image': backend.image['image_id'] = 'wrong'
            else: backend.capacity['host_free_disk_bytes'] = 0
            self.assertNotEqual(o.orchestrate(backend)['status'], 'MOCK_EXECUTION_ONLY')
            self.assertNotIn('compile_dsh', backend.calls)

    def test_resource_gate_precedes_materialization(self):
        backend = FixtureBackend(mutate=lambda obs: obs.update(storage_capability='UNKNOWN'))
        self.assertEqual(o.orchestrate(backend)['status'], 'TASK_RESOURCE_BINDING_FAILURE')
        self.assertNotIn('materialize', backend.calls); self.assertNotIn('native_probe', backend.calls)

    def test_cleanup_failure_not_pass(self):
        self.assertEqual(o.orchestrate(FixtureBackend('cleanup'))['status'], 'EVIDENCE_INDETERMINATE')

    def test_raw_failure_values_not_safe_summary(self):
        backend = FixtureBackend('prepare'); result = o.orchestrate(backend)
        self.assertEqual(result['error_code'], 'FIXTURE_FAILURE')
        with patch.object(backend, 'prepare', side_effect=RuntimeError('private-value')):
            result = o.orchestrate(backend)
        self.assertNotIn('private-value', json.dumps(result))

    def test_bulk_scan_failure_independent_safe_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)/'work'; work.mkdir(); (work/'raw').mkdir()
            (work/'summary.json').write_bytes(a.canonical({'status':'NO_MODEL_RUNTIME_QUALIFIED'}))
            def scan(path, **kwargs): return ['fixture rejection'] if path.name == 'raw' else []
            with patch.object(a,'scan_tree',side_effect=scan):
                flags = o.export_evidence(work, Path(tmp)/'published', {'run':'1'})
            self.assertEqual(flags, {'safe':True,'bulk':False,'program':False})
            core = json.loads((Path(tmp)/'published/safe-core/summary.json').read_bytes())
            self.assertEqual(core['summary']['status'], 'EVIDENCE_INDETERMINATE')
            self.assertFalse((Path(tmp)/'published/bulk').exists())

    def test_missing_bundle_preserves_safe_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp)/'work'; work.mkdir(); (work/'raw').mkdir()
            (work/'summary.json').write_bytes(a.canonical({'status':'NO_MODEL_RUNTIME_QUALIFIED'}))
            flags=o.export_evidence(work,Path(tmp)/'published',{'run':'1'})
            self.assertTrue(flags['safe']); self.assertFalse(flags['program'])
            self.assertEqual(json.loads((Path(tmp)/'published/safe-core/summary.json').read_bytes())['summary']['status'], 'ARTIFACT_INTEGRITY_FAILURE')

    def test_entrypoint_no_external_locally(self):
        with patch.dict(o.os.environ, {}, clear=True), patch.object(o.sys,'argv',['probe','run']), patch.object(o,'RealBackend') as backend:
            with self.assertRaisesRegex(a.ArtifactError,'EXTERNAL_WORKFLOW_BOUNDARY_REQUIRED'): o.main()
            backend.assert_not_called()

    def test_workflow_fixed_manual_boundary(self):
        text=(i.ROOT/'.github/workflows/gha-m1c1-runtime-artifact.yml').read_text()
        self.assertIn('workflow_dispatch:',text); self.assertNotIn('inputs:',text)
        for forbidden in ('DEEPSEEK_API_KEY','gha-m1c1-live.yml','127.0.0.1:10090'):
            self.assertNotIn(forbidden,text)
        self.assertIn('11537937939/zip',text)
        self.assertIn('steps.evidence.outputs.safe',text)

    def test_checkout_only_exact_preflight_files_allowed(self):
        sha = 'a'*40
        o.checkout_gate(sha,sha,False,['work/census.zip','reports/artifact-harbor.json'])
        for actual, expected, dirty, paths in [(sha,'b'*40,False,[]), (sha,sha,True,[]),
                                               (sha,sha,False,['scripts/untracked.py'])]:
            with self.subTest(paths=paths), self.assertRaises(a.ArtifactError):
                o.checkout_gate(actual,expected,dirty,paths)

    def test_protected_source_unchanged(self):
        self.assertEqual(a.file_hash(i.ROOT/'evaluation/agents/dsh_harbor_adapter/adapter.py'),
                         '8ef6389565309ba208557923cced1e619a8a1b25549353f9b5f13e2313ad6070')
        self.assertEqual(a.file_hash(i.ROOT/'configs/experiment_task_exclusions_v1.json'),
                         '4791ea562b79392618c0da2dfd01ae7054267505124753d913c07e4a604e6e6b')

    def test_installed_backend_source_capability_readonly(self):
        evidence = r.backend_evidence(); policy = r.backend_policy()
        self.assertEqual(evidence['version'], '0.21.0')
        self.assertEqual(evidence['sources'], policy['backend_sources'])
        self.assertEqual(evidence['environment_tree_sha256'], policy['environment_tree_sha256'])
        self.assertFalse(evidence['storage_quota_parameter'])

    def test_runtime_imports_no_agent_or_verifier(self):
        import ast
        tree = ast.parse((i.ROOT/'scripts/m1c_runtime_orchestrator.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)]
        for name in imports:
            self.assertFalse(name and any(part in name for part in ('harbor.agents','harbor.verifier','harbor.trial.trial')))
        manifest=(i.ROOT/'PUBLICATION_MANIFEST.txt').read_text().splitlines()
        for path in ('scripts/m1c_runtime_orchestrator.py','scripts/m1c_runtime_resources.py',
                     'configs/m1c_runtime_backend_v1.json','.github/workflows/gha-m1c1-runtime-artifact.yml',
                     'evaluation/tests/test_m1c_runtime_orchestration.py'):
            self.assertEqual(manifest.count(path),1)


class BuilderEnvironmentTests(unittest.TestCase):
    """Synthetic pinned-config fixtures, never public metadata GET or Docker."""
    def setUp(self):
        self.value = 'A' * 40  # Deliberately not the real upstream identifier.
        self.config = {'os': 'linux', 'architecture': 'amd64',
                       'config': {'Env': ['PATH=/usr/bin', 'LANG=C.UTF-8', 'GPG_KEY=' + self.value]},
                       'history': [{'created_by': 'fixture'} for _ in range(11)]}
        self.raw = a.canonical(self.config)
        self.patchers = [patch.object(e, 'CONFIG', a.digest(self.raw)),
                         patch.object(e, 'VALUE', a.digest(self.value.encode())),
                         patch.object(e, 'HISTORY', {7: a.digest(b'fixture'), 10: a.digest(b'fixture')})]
        for p in self.patchers: p.start(); self.addCleanup(p.stop)
        self.p = i.policy(); self.p['base_config_digest'] = 'sha256:' + e.CONFIG
        self.id = 'sha256:' + 'a' * 64
        self.image = {'Id': self.id, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {
            'Env': ['PATH=/opt/pinned-node/bin:/usr/bin', 'LANG=C.UTF-8', 'GPG_KEY=' + self.value],
            'Labels': {'m1c.base': e.BASE, 'm1c.context': self.p['context_sha256']}, 'Entrypoint': None}}
        self.container = {'Image': self.id, 'Config': copy.deepcopy(self.image['Config'])}
        self.container['Config']['Cmd'] = ['/bin/sleep', 'infinity']
        self.argv = ['docker', 'create', '--platform=linux/amd64', '--memory', '8589934592',
                     '--memory-swap', '8589934592', '--cpus', '2', '--mount', 'fixture1',
                     '--mount', 'fixture2', '--mount', 'fixture3', self.id, '/bin/sleep', 'infinity']

    def metadata(self):
        return e.builder_metadata(self.image, self.id, self.p, self.raw)

    def test_authenticated_metadata_receipt_contains_no_value(self):
        receipt = self.metadata()
        self.assertEqual(receipt['classification'], 'UPSTREAM_NONSECRET_IMAGE_METADATA')
        self.assertNotIn(self.value, json.dumps(receipt))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'receipt.json').write_bytes(a.canonical(receipt))
            self.assertFalse(a.scan_tree(Path(tmp), artifact_mode=True))

    def test_unknown_modified_private_identifier_rejected(self):
        for value in ('unknown', 'B'*40, '-----BEGIN PRIVATE KEY-----'):
            with self.subTest(value_type=len(value)):
                self.image['Config']['Env'][-1] = 'GPG_KEY=' + value
                with self.assertRaises(a.ArtifactError): self.metadata()

    def test_wrong_identity_and_missing_provenance_rejected(self):
        for field, value in [('base_image', 'wrong'), ('base_config_digest', 'sha256:'+'0'*64)]:
            original = self.p[field]; self.p[field] = value
            with self.assertRaises(a.ArtifactError): self.metadata()
            self.p[field] = original
        self.raw = b'{}'
        with self.assertRaises(a.ArtifactError): self.metadata()

    def test_platform_label_and_image_id_drift_blocked(self):
        for field, value in [('Id', 'sha256:'+'b'*64), ('Architecture', 'arm64')]:
            original = self.image[field]; self.image[field] = value
            with self.assertRaises(a.ArtifactError): self.metadata()
            self.image[field] = original
        self.image['Config']['Labels']['m1c.base'] = 'wrong'
        with self.assertRaises(a.ArtifactError): self.metadata()

    def test_other_credential_names_unchanged(self):
        for name in ('OTHER_KEY', 'GPG_OTHER', 'TOKEN', 'AUTHORIZATION', 'PROXY', 'NODE_OPTIONS'):
            self.image['Config']['Env'].append(name+'=fixture')
            with self.assertRaises(a.ArtifactError): self.metadata()
            self.image['Config']['Env'].pop()
        for name in ('GPG_KEY', 'OTHER_KEY', 'TOKEN', 'AUTH', 'PASSWORD', 'COOKIE', 'PROXY'):
            with self.assertRaises(a.ArtifactError): o.RealBackend._check_environment([name+'=fixture'])

    def test_correct_value_wrong_runtime_context_still_blocked(self):
        self.metadata()
        with self.assertRaises(a.ArtifactError): e.strict(['GPG_KEY='+self.value])
        with self.assertRaises(a.ArtifactError): e.process_environment(['GPG_KEY='+self.value])
        with self.assertRaises(a.ArtifactError): e.container_environment(self.container, self.image, self.id,
            self.argv[:-3]+['--env', 'GPG_KEY='+self.value]+self.argv[-3:])

    def test_container_overrides_or_duplicate_names_blocked(self):
        self.metadata()
        e.container_environment(self.container, self.image, self.id, self.argv)
        self.container['Config']['Env'].append('GPG_KEY='+self.value)
        with self.assertRaises(a.ArtifactError): e.container_environment(self.container, self.image, self.id, self.argv)
        self.container['Config']['Env'][-1] = 'UNEXPECTED=fixture'
        with self.assertRaises(a.ArtifactError): e.container_environment(self.container, self.image, self.id, self.argv)

    def test_effective_environment_excludes_metadata(self):
        rows = [k+'='+v for k,v in e.PROCESS_ENV.items()]
        e.process_environment(rows)
        for extra in ('GPG_KEY='+self.value, 'UNEXPECTED=fixture', 'NODE_OPTIONS=fixture'):
            with self.assertRaises(a.ArtifactError): e.process_environment(rows+[extra])
        backend = o.RealBackend.__new__(o.RealBackend); backend.builder = 'fixture'
        backend.call = unittest.mock.Mock(return_value='')
        backend.builder_exec(['pnpm','run','build'])
        argv = backend.call.call_args.args[0]
        self.assertIn('-i', argv); self.assertFalse(any('GPG_KEY' in x for x in argv))

    def test_environment_failure_blocks_dsh_gate(self):
        backend = o.RealBackend.__new__(o.RealBackend)
        backend.builder_environment_gate = unittest.mock.Mock(side_effect=a.ArtifactError('BUILDER_RUNTIME_INJECTION'))
        with patch.object(i, 'dsh_build_gate') as gate, self.assertRaises(a.ArtifactError):
            backend.build_gate({}, {})
        gate.assert_not_called()

    def test_public_fetch_is_not_reached_by_local_fixtures(self):
        with patch.object(e.urllib.request, 'build_opener', side_effect=AssertionError('network forbidden')):
            self.metadata()

    def test_fetch_errors_are_symbolic_without_value(self):
        opener = unittest.mock.Mock(); opener.open.side_effect = RuntimeError('synthetic-private-value')
        with patch.object(e.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(a.ArtifactError, '^UPSTREAM_PUBLIC_METADATA_UNAVAILABLE$'):
                e.public_config()

    def test_no_scanner_or_artifact_class_changes(self):
        # Hash anchors, not another shallow-checkout Git-history dependency.
        expected = {'scripts/public_secret_scan.py': 'eb5e02ac30dfc6aa29bcd34be4628b7947caa107869cb88dee03366cc22bc974',
            'scripts/m1c_runtime_artifact.py': 'f3b75663ac20829ee7ebde25b0c08b2e1c655ec8ec22adc325633e23bfb465db',
            'scripts/m1c_runtime_builder.py': '86d271343877db6b176b88fa057591a103f1d0afc5ba0f1efcfa2c94b2ff4178',
            'scripts/m1c_runtime_qualification.py': '4554868346668f0a0f4ede5061a0199510deb4b7d58f0de456617de2349f65d3',
            'evaluation/agents/dsh_harbor_adapter/adapter.py': a.ADAPTER_SHA}
        for path, expected_hash in expected.items():
            self.assertEqual(a.file_hash(i.ROOT/path), expected_hash)

    def test_signing_purpose_required_even_when_config_hash_matches(self):
        self.config['history'][10]['created_by'] = 'different-purpose'
        self.raw = a.canonical(self.config)
        with patch.object(e, 'CONFIG', a.digest(self.raw)):
            self.p['base_config_digest'] = 'sha256:' + e.CONFIG
            with self.assertRaisesRegex(a.ArtifactError, 'SIGNING_PURPOSE'): self.metadata()

    def test_platform_required_even_when_config_hash_matches(self):
        self.config['architecture'] = 'arm64'; self.raw = a.canonical(self.config)
        with patch.object(e, 'CONFIG', a.digest(self.raw)):
            self.p['base_config_digest'] = 'sha256:' + e.CONFIG
            with self.assertRaisesRegex(a.ArtifactError, 'PLATFORM'): self.metadata()

    def test_no_format_only_or_private_material_exception(self):
        for value in ('B'*40, '-----BEGIN PRIVATE KEY-----'):
            self.config['config']['Env'][-1] = 'GPG_KEY=' + value; self.raw = a.canonical(self.config)
            with patch.object(e, 'CONFIG', a.digest(self.raw)):
                self.p['base_config_digest'] = 'sha256:' + e.CONFIG
                with self.assertRaises(a.ArtifactError): self.metadata()

    def test_duplicate_upstream_metadata_rejected(self):
        self.config['config']['Env'].append('GPG_KEY='+self.value); self.raw = a.canonical(self.config)
        with patch.object(e, 'CONFIG', a.digest(self.raw)):
            self.p['base_config_digest'] = 'sha256:' + e.CONFIG
            with self.assertRaisesRegex(a.ArtifactError, 'DUPLICATE'): self.metadata()

    def test_build_gate_rechecks_actual_container_not_just_receipt(self):
        backend = o.RealBackend.__new__(o.RealBackend)
        backend.image_id = self.id; backend.p = self.p; backend.builder = 'fixture'
        backend.upstream_config = self.raw; backend.builder_metadata_receipt = self.metadata()
        backend.builder_create_argv = self.argv; backend.child_env = {'PATH': '/usr/bin'}
        backend.inspect = lambda target, image=False: self.image if image else self.container
        backend.builder_environment_gate()
        self.container['Config']['Env'][-1] = 'GPG_KEY='+'B'*40
        with patch.object(i, 'dsh_build_gate') as gate, self.assertRaises(a.ArtifactError):
            backend.build_gate({}, {})
        gate.assert_not_called()

    def test_untrusted_host_child_environment_cannot_inherit_metadata_trust(self):
        backend = o.RealBackend.__new__(o.RealBackend)
        backend.image_id = self.id; backend.p = self.p; backend.builder = 'fixture'
        backend.upstream_config = self.raw; backend.builder_metadata_receipt = self.metadata()
        backend.builder_create_argv = self.argv; backend.child_env = {'GPG_KEY': self.value}
        backend.inspect = lambda target, image=False: self.image if image else self.container
        with self.assertRaisesRegex(a.ArtifactError, 'CREDENTIAL'): backend.builder_environment_gate()


if __name__ == '__main__': unittest.main()
