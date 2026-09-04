import json, shlex, uuid
from pathlib import Path, PurePosixPath
from typing import Any, override
from harbor.agents.installed.base import BaseInstalledAgent, with_prompt_template
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext
from harbor.models.agent.name import AgentName
from harbor.models.trajectories import Agent, Step, Trajectory
from harbor.utils.trajectory_utils import format_trajectory_json

class DshHarborAdapter(BaseInstalledAgent):
    SUPPORTS_ATIF=True
    SUPPORTS_CONFIG=True
    DSH_COMMIT="b150a551b8d465e31e418e1b2eaf5e79bbb7d28e"
    REMOTE=PurePosixPath("/installed-agent/deepseek-harness")
    @staticmethod
    def name(): return "dsh-harbor-adapter-v1"
    def get_version_command(self): return f"node {self.REMOTE}/apps/cli/lib/bin.js --version"
    async def install(self, environment: BaseEnvironment):
        await self.ensure_system_dependencies(environment,("curl","bash","git","nodejs","npm","ca_certificates"))
        cmd=("set -euo pipefail; export COREPACK_ENABLE_DOWNLOAD_PROMPT=0; "
             "node -e 'const [a,b]=process.versions.node.split(`.`).map(Number);process.exit(a>22||(a===22&&b>=19)?0:1)' || "
             "{ curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && apt-get install -y nodejs; }; "
             f"rm -rf {self.REMOTE}; git clone --filter=blob:none https://github.com/deepseek-ai/deepseek-harness.git {self.REMOTE}; "
             f"git -C {self.REMOTE} checkout --detach {self.DSH_COMMIT}; corepack enable; cd {self.REMOTE}; pnpm install --frozen-lockfile; pnpm run build")
        await self.exec_as_root(environment,command=cmd,timeout_sec=1800)
    @override
    @with_prompt_template
    async def run(self,instruction:str,environment:BaseEnvironment,context:AgentContext):
        cfg=self.config_source if isinstance(self.config_source,dict) else {}
        if cfg.get("base_dsh_commit")!=self.DSH_COMMIT: raise ValueError("DSH commit mismatch")
        patch=str(cfg.get("cordis_patch","plugins: []\n"))
        await self._upload_config_text(environment,content=patch,remote_path="/installed-agent/candidate.patch.yml",filename="candidate.patch.yml")
        sid=str(uuid.uuid4()); context.session_id=sid
        home="/logs/agent/dsh-home"; events="/logs/agent/dsh-events"
        env={"DSH_HOME":home,"DSH_TELEMETRY_DISABLED":"1","DSH_PERMISSION_MODE":"workspace-write"}
        credential_name=cfg.get("credential_environment_name")
        if not isinstance(credential_name,str) or not credential_name:
            raise ValueError("credential_environment_name is required")
        env[credential_name]=self._get_env(credential_name) or ""
        command=(f"mkdir -p {home} {events}; cd /app; node {self.REMOTE}/apps/cli/lib/bin.js --profile headless --patch /installed-agent/candidate.patch.yml {shlex.quote(instruction)} </dev/null > /logs/agent/stdout.txt 2> /logs/agent/stderr.txt")
        await self.exec_as_agent(environment,command=command,env=env,timeout_sec=int(cfg.get("timeout_sec",1800)))
        self._session_id=sid; self._instruction=instruction
    def populate_context_post_run(self,context:AgentContext):
        sid=getattr(self,"_session_id",str(uuid.uuid4()))
        trajectory=Trajectory(schema_version="ATIF-v1.7",session_id=sid,agent=Agent(name=self.name(),version="1.0.0",model_name=self.model_name),steps=[Step(step_id=1,source="user",message=getattr(self,"_instruction",""))])
        (self.logs_dir/"trajectory.json").write_text(format_trajectory_json(trajectory.to_json_dict()))
