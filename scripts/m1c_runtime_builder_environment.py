"""Builder-only public metadata trust boundary. Importing performs no I/O.

Bindings transcribed from the independently verified 2026-10-08 OCI report,
not from a name/hex heuristic. Raw metadata/token/value never enter receipts.
"""
import json
import re
import urllib.request
from urllib.parse import urlsplit
from scripts import m1c_runtime_artifact as a

BASE = 'docker.io/library/python@sha256:297452d603034817c2a94bce91875a4c06fb0f7faefd4d2bd9fa22b393ef9574'
CONFIG = 'd0305d03a42543c1a85755043645e45fc47049ad96b51224a8530c055401e88a'
VALUE = '02978be54c8be7cdd4dfcb2b4d291fbc9e5023a9a2b9ca0d1576361904fe81d3'
HISTORY = {7: 'df2ad7899c0ba00a615a32ec282521f138e2005ceb825ed59624d1c0ac458982',
           10: 'c4b1b2bb5edf6bdc2b1999e70b820d4ef6c7762e5d8d8c1b21c378dad44041a1'}
PROCESS_ENV = {'PATH': '/opt/pinned-node/bin:/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp'}


def environment(rows):
    a.require(isinstance(rows, list) and all(isinstance(x, str) and '=' in x for x in rows), 'ENVIRONMENT_SCHEMA')
    result = dict(row.split('=', 1) for row in rows)
    a.require(len(result) == len(rows), 'ENVIRONMENT_DUPLICATE')
    return result


def strict(rows):
    names = environment(rows)
    a.require(not any(re.search(r'KEY|TOKEN|SECRET|AUTH|PASSWORD|COOKIE|PROXY', n, re.I) or
                     n in {'NODE_OPTIONS', 'NODE_PATH', 'LD_LIBRARY_PATH'} for n in names),
              'CREDENTIAL_OR_ENVIRONMENT_DRIFT')


def verify_config(raw, policy):
    a.require(policy['base_image'] == BASE and policy['base_config_digest'] == 'sha256:' + CONFIG,
              'UPSTREAM_OCI_IDENTITY_DRIFT')
    a.require(a.digest(raw) == CONFIG, 'UPSTREAM_CONFIG_HASH_MISMATCH')
    config = json.loads(raw)
    a.require(config['os'] == 'linux' and config['architecture'] == 'amd64', 'UPSTREAM_PLATFORM_DRIFT')
    env = environment(config['config']['Env'])
    value = env.get('GPG_KEY', '')
    a.require(bool(re.fullmatch(r'[0-9A-F]{40}', value)) and a.digest(value.encode()) == VALUE,
              'UPSTREAM_PUBLIC_IDENTIFIER_MISMATCH')
    strict([k + '=' + v for k, v in env.items() if k != 'GPG_KEY'])
    for index, expected in HISTORY.items():
        a.require(a.digest(config['history'][index]['created_by'].encode()) == expected,
                  'UPSTREAM_SIGNING_PURPOSE_MISMATCH')
    return {'classification': 'UPSTREAM_NONSECRET_IMAGE_METADATA', 'base_image': BASE,
            'config_sha256': CONFIG, 'identifier_sha256': VALUE,
            'signing_history_sha256': {str(k): v for k, v in HISTORY.items()}}


def public_config():
    """Future authorized workflow only: fixed public config GET, never layers.

    Anonymous public-library token stays in memory. No inherited proxy and no
    Authorization forwarded to CDN redirects; network errors are symbolic.
    """
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            url = urlsplit(newurl)
            a.require(url.scheme == 'https' and url.hostname == 'production.cloudfront.docker.com' and
                      not url.username and not url.password, 'PUBLIC_METADATA_REDIRECT_REJECTED')
            return urllib.request.Request(newurl)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    def get(url, headers=None):
        with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
            a.require(len(raw) <= 1024 * 1024, 'PUBLIC_METADATA_SIZE_REJECTED')
            return raw
    try:
        token = json.loads(get('https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fpython%3Apull'))['token']
        raw = get('https://registry-1.docker.io/v2/library/python/blobs/sha256:' + CONFIG,
                  {'Authorization': 'Bearer ' + token})
    except Exception:
        # Do not retain exception URLs, response bodies, tokens or headers.
        raw = None
    a.require(raw is not None, 'UPSTREAM_PUBLIC_METADATA_UNAVAILABLE')
    return raw


def builder_metadata(image, image_id, policy, raw):
    receipt = verify_config(raw, policy)
    labels = image['Config']['Labels']
    a.require(image['Id'] == image_id and a.DIGEST.fullmatch(image_id) and
              image['Os'] == 'linux' and image['Architecture'] == 'amd64' and
              labels['m1c.base'] == BASE and labels['m1c.context'] == policy['context_sha256'],
              'BUILDER_METADATA_IDENTITY_DRIFT')
    env = environment(image['Config']['Env'])
    a.require('GPG_KEY' in env and a.digest(env['GPG_KEY'].encode()) == VALUE,
              'BUILDER_PUBLIC_IDENTIFIER_DRIFT')
    # All inherited entries except the audited Dockerfile PATH must match the
    # authenticated config. No new benign-looking variable gets a free pass.
    expected = environment(json.loads(raw)['config']['Env'])
    expected['PATH'] = '/opt/pinned-node/bin:' + expected['PATH']
    a.require(env == expected, 'BUILDER_IMAGE_ENVIRONMENT_DRIFT')
    strict([k + '=' + v for k, v in env.items() if k != 'GPG_KEY'])
    return dict(receipt, image_id=image_id, image_environment_sha256=a.digest(a.canonical(env)))


def container_environment(container, image, image_id, create_argv):
    # Only the controller's fixed create path may inherit image metadata.
    # No user-provided -e/--env/--env-file, alternate entrypoint or shell path.
    a.require(len(create_argv) == 18 and
              [create_argv[x] for x in (3, 5, 7, 9, 11, 13)] ==
              ['--memory', '--memory-swap', '--cpus', '--mount', '--mount', '--mount'] and
              create_argv[:3] == ['docker', 'create', '--platform=linux/amd64'] and
              create_argv[-3:] == [image_id, '/bin/sleep', 'infinity'] and
              all(x not in {'-e', '--env', '--env-file', '--entrypoint'} and
                  not x.startswith(('--env=', '--env-file=', '--entrypoint=', '-e='))
                  for x in create_argv), 'BUILDER_RUNTIME_INJECTION')
    a.require(container['Image'] == image_id and
              environment(container['Config']['Env']) == environment(image['Config']['Env']) and
              container['Config'].get('Entrypoint') == image['Config'].get('Entrypoint') and
              container['Config']['Cmd'] == ['/bin/sleep', 'infinity'], 'BUILDER_CONTAINER_ENVIRONMENT_DRIFT')


def process_environment(rows):
    strict(rows)
    a.require(environment(rows) == PROCESS_ENV, 'BUILDER_PROCESS_ENVIRONMENT_DRIFT')
