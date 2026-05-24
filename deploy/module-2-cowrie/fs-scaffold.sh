#!/usr/bin/env bash
# fs-scaffold.sh — Populate the fake Cowrie filesystem on the VPS
#
# Run ONCE from /opt/honeypot/deploy/module-2-cowrie/ before bringing up Module 2.
# Creates the deceptive AI/ML training server directory structure under
# /opt/honeypot/honeypot/cowrie/fs/ which mounts read-only into Cowrie at /cowrie/honeyfs/.
#
# USAGE:
#   cd /opt/honeypot/deploy/module-2-cowrie/
#   sudo bash fs-scaffold.sh
#
# IMPORTANT:
#   All created files and directories are chowned to 100000:100000 (userns-remap dockremap UID).
#   If you re-run this script it will overwrite existing files without confirmation.

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# Adjust BASE_DIR only if your project root differs from /opt/honeypot/
BASE_DIR="/opt/honeypot"
FS_ROOT="${BASE_DIR}/honeypot/cowrie/fs"
REMAP_UID=100000
REMAP_GID=100000

# ── Pre-flight checks ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (it sets ownership to UID ${REMAP_UID})"
  exit 1
fi

if [[ ! -d "${BASE_DIR}" ]]; then
  echo "ERROR: Project root ${BASE_DIR} does not exist. Run Module 0 bootstrap first."
  exit 1
fi

echo "[fs-scaffold] Creating fake filesystem under ${FS_ROOT}"
echo "[fs-scaffold] All files will be owned ${REMAP_UID}:${REMAP_GID}"

# ── Directory structure ────────────────────────────────────────────────────────
# Cowrie maps this tree to /root/ inside the fake shell (honeyfs/root/ → ~/)
# Standard OS directories are handled by Cowrie's built-in honeyfs;
# we only need to populate the deception-specific content.

ROOT_HOME="${FS_ROOT}/root"

mkdir -p \
  "${ROOT_HOME}/training_runs/run_2026-04-15/checkpoints" \
  "${ROOT_HOME}/training_runs/run_2026-04-15/logs" \
  "${ROOT_HOME}/training_runs/run_2026-05-01/checkpoints" \
  "${ROOT_HOME}/training_runs/run_2026-05-01/logs" \
  "${ROOT_HOME}/models/llama-7b-weights" \
  "${ROOT_HOME}/scripts" \
  "${ROOT_HOME}/.config/wandb" \
  "${ROOT_HOME}/.config/neuro"

# ── Training run artifacts ─────────────────────────────────────────────────────
cat > "${ROOT_HOME}/training_runs/run_2026-04-15/config.yaml" <<'EOF'
# LLaMA 7B fine-tune — Neuro internal corpus v3
run_name: neuro-llama7b-finetune-20260415
base_model: meta-llama/Llama-2-7b-hf
dataset: neuro-internal/security-corpus-v3
output_dir: /data/models/llama-7b-finetuned
num_epochs: 3
per_device_train_batch_size: 4
gradient_accumulation_steps: 8
learning_rate: 2.0e-5
fp16: true
seed: 42
wandb_project: neuro-llm
wandb_entity: neuro-ai
EOF

cat > "${ROOT_HOME}/training_runs/run_2026-04-15/logs/train_metrics.jsonl" <<'EOF'
{"epoch": 1, "loss": 2.1843, "learning_rate": 2e-05, "step": 500, "gpu_util": 94.2}
{"epoch": 1, "loss": 1.9217, "learning_rate": 1.8e-05, "step": 1000, "gpu_util": 95.1}
{"epoch": 2, "loss": 1.6452, "learning_rate": 1.2e-05, "step": 1500, "gpu_util": 93.7}
{"epoch": 2, "loss": 1.4831, "learning_rate": 8e-06, "step": 2000, "gpu_util": 96.0}
{"epoch": 3, "loss": 1.3209, "learning_rate": 4e-06, "step": 2500, "gpu_util": 94.8}
{"epoch": 3, "loss": 1.2784, "learning_rate": 2e-06, "step": 3000, "gpu_util": 95.3}
EOF

cat > "${ROOT_HOME}/training_runs/run_2026-04-15/checkpoints/README" <<'EOF'
Checkpoints for run_2026-04-15 (LLaMA-7B fine-tune epoch 1-3).
Best checkpoint: step-2500 (val_loss=1.1932)
Promoted to: /models/llama-7b-weights/ on 2026-04-22
EOF

cat > "${ROOT_HOME}/training_runs/run_2026-05-01/config.yaml" <<'EOF'
# LLaMA 7B v2 fine-tune — extended dataset + RLHF alignment pass
run_name: neuro-llama7b-v2-rlhf-20260501
base_model: /models/llama-7b-weights
dataset: neuro-internal/security-corpus-v4
alignment: rlhf
reward_model: neuro-internal/reward-model-v1
output_dir: /data/models/llama-7b-v2-rlhf
num_epochs: 2
per_device_train_batch_size: 2
learning_rate: 5.0e-6
fp16: true
seed: 7
wandb_project: neuro-llm
wandb_entity: neuro-ai
EOF

cat > "${ROOT_HOME}/training_runs/run_2026-05-01/logs/train_metrics.jsonl" <<'EOF'
{"epoch": 1, "loss": 1.1243, "reward": 0.423, "step": 200, "gpu_util": 91.3}
{"epoch": 1, "loss": 0.9871, "reward": 0.581, "step": 400, "gpu_util": 92.7}
{"epoch": 2, "loss": 0.8934, "reward": 0.672, "step": 600, "gpu_util": 93.1}
EOF

# ── Model weights placeholder ──────────────────────────────────────────────────
# These are zero-byte placeholder files. Real weights would be multi-GB binaries.
# The directory structure is realistic enough to deceive attackers who ls -la.
for f in \
  "config.json" \
  "generation_config.json" \
  "tokenizer.json" \
  "tokenizer_config.json" \
  "special_tokens_map.json" \
  "pytorch_model-00001-of-00003.bin" \
  "pytorch_model-00002-of-00003.bin" \
  "pytorch_model-00003-of-00003.bin" \
  "pytorch_model.bin.index.json"; do
  touch "${ROOT_HOME}/models/llama-7b-weights/${f}"
done

cat > "${ROOT_HOME}/models/llama-7b-weights/config.json" <<'EOF'
{
  "architectures": ["LlamaForCausalLM"],
  "bos_token_id": 1,
  "eos_token_id": 2,
  "hidden_size": 4096,
  "intermediate_size": 11008,
  "max_position_embeddings": 4096,
  "model_type": "llama",
  "num_attention_heads": 32,
  "num_hidden_layers": 32,
  "rms_norm_eps": 1e-05,
  "transformers_version": "4.31.0",
  "vocab_size": 32000
}
EOF

cat > "${ROOT_HOME}/models/llama-7b-weights/README.md" <<'EOF'
# LLaMA 7B — Neuro Fine-tuned Weights

Internal model. DO NOT distribute outside Neuro AI infrastructure.
Access controlled by svc-deploy service account.

Origin: Meta LLaMA 2 7B base + Neuro security corpus fine-tune (run_2026-04-15)
Contact: m.chen@neuro.ai (ML Platform), priya.nair@neuro.ai (Training Infra)
EOF

# ── Fake .env with canary API keys ────────────────────────────────────────────
# IMPORTANT: These are intentionally fake placeholder values.
# They follow realistic formatting (length, prefix) but are NOT valid credentials.
# The sk-ant- and sk- prefixes are recognizable to attackers — that's the point.
# Real operators: do NOT substitute real keys here.
cat > "${ROOT_HOME}/.env" <<'EOF'
# Neuro neurocore-gpu01 — service credentials
# Generated by svc-deploy — DO NOT commit to git

# Anthropic API key (model serving + eval)
ANTHROPIC_API_KEY=sk-ant-REPLACEME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx01

# OpenAI API key (comparison eval baseline)
OPENAI_API_KEY=sk-REPLACEME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx01

# Weights & Biases
WANDB_API_KEY=local-REPLACEME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
WANDB_PROJECT=neuro-llm
WANDB_ENTITY=neuro-ai

# Internal model registry
MODEL_REGISTRY_URL=https://registry.neuro.ai
MODEL_REGISTRY_TOKEN=neuro-reg-REPLACEME-xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# PostgreSQL (training metadata)
DATABASE_URL=postgresql://svc_train:REPLACEME-db-password@neuro-db-01.internal:5432/training_meta

# HuggingFace (base model downloads)
HUGGINGFACE_TOKEN=hf_REPLACEME_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# S3-compatible object storage (checkpoint dumps)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REPLACEME
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/REPLACEME+KEY+HERE
AWS_DEFAULT_REGION=us-east-1
S3_CHECKPOINT_BUCKET=neuro-model-checkpoints

# Slack alerting (training job notifications)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REPLACEME/REPLACEME/REPLACEME
EOF

# ── Fake training script ───────────────────────────────────────────────────────
cat > "${ROOT_HOME}/scripts/train.py" <<'EOF'
#!/usr/bin/env python3
"""
Neuro AI — LLaMA fine-tune training script
Usage: python3 train.py --config /root/training_runs/<run>/config.yaml
"""
import os
import sys
import json
import time
import argparse
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Neuro LLM fine-tune trainer")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument("--resume", default=None, help="Resume from checkpoint path")
    parser.add_argument("--dry-run", action="store_true", help="Validate config only")
    return parser.parse_args()

def load_config(path):
    """Load YAML config (simplified — real version uses PyYAML)."""
    print(f"[{datetime.utcnow().isoformat()}Z] Loading config: {path}")
    if not os.path.exists(path):
        sys.exit(f"ERROR: Config not found: {path}")
    return {}

def check_env():
    """Validate required environment variables."""
    required = ["ANTHROPIC_API_KEY", "WANDB_API_KEY", "DATABASE_URL"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        sys.exit(f"ERROR: Missing env vars: {missing}\nSee /root/.env")

def main():
    args = parse_args()
    check_env()
    config = load_config(args.config)

    if args.dry_run:
        print("Dry-run: config valid. Exiting.")
        return

    print(f"[{datetime.utcnow().isoformat()}Z] Initializing training run...")
    print(f"[{datetime.utcnow().isoformat()}Z] GPU: NVIDIA A100 80GB × 4")
    print(f"[{datetime.utcnow().isoformat()}Z] W&B run: https://wandb.ai/neuro-ai/neuro-llm/runs/placeholder")
    print(f"[{datetime.utcnow().isoformat()}Z] Training started — press Ctrl+C to interrupt")

    # Stub — real training loop is in Dockerfile CMD
    for step in range(1, 101):
        time.sleep(0.1)
        if step % 10 == 0:
            loss = round(2.5 - (step / 100.0), 4)
            print(f"step={step:4d}  loss={loss:.4f}  lr=2.0e-05", flush=True)

if __name__ == "__main__":
    main()
EOF

# ── MariaDB app config (kill-chain pivot lure) ────────────────────────────────
# IMPORTANT: Replace REPLACEME-neuro-app-password with the actual MARIADB_PASSWORD
# from deploy/module-4-mariadb-lure/.env BEFORE bringing up Cowrie.
# On VPS:
#   NEURO_APP_PASS=$(sudo grep '^MARIADB_PASSWORD=' /opt/honeypot/deploy/module-4-mariadb-lure/.env | cut -d= -f2)
#   sudo sed -i "s/REPLACEME-neuro-app-password/${NEURO_APP_PASS}/" \
#     /opt/honeypot/honeypot/cowrie/fs/root/.config/neuro/config.yaml \
#     /opt/honeypot/honeypot/cowrie/fs/root/.bash_history
#   sudo chown -R 100000:100000 /opt/honeypot/honeypot/cowrie/fs/root/.config /opt/honeypot/honeypot/cowrie/fs/root/.bash_history
cat > "${ROOT_HOME}/.config/neuro/config.yaml" <<'EOF'
# Neuro platform config — neurocore-gpu01
# Generated by deploy/scripts/gen-config.sh — DO NOT COMMIT
environment: production

database:
  host: 10.0.0.5
  port: 3306
  name: neuro_prod
  user: neuro_app
  password: REPLACEME-neuro-app-password

redis:
  host: 10.0.0.6
  port: 6379

logging:
  level: info
  output: /var/log/neuro/shipper.log
EOF

# ── Bash history (most attackers run `history` or `cat ~/.bash_history` immediately) ──
cat > "${ROOT_HOME}/.bash_history" <<'EOF'
ls -la
df -h
docker ps
cd /root/.config/neuro
cat config.yaml
mariadb -h 10.0.0.5 -u neuro_app -pREPLACEME-neuro-app-password neuro_prod
show tables;
select count(*) from training_runs;
exit
EOF

# ── W&B config stub ────────────────────────────────────────────────────────────
cat > "${ROOT_HOME}/.config/wandb/settings" <<'EOF'
[default]
entity = neuro-ai
project = neuro-llm
base_url = https://api.wandb.ai
anonymous = false
EOF

# ── Apply userns-remap ownership ──────────────────────────────────────────────
echo "[fs-scaffold] Applying ownership ${REMAP_UID}:${REMAP_GID} to ${FS_ROOT}"
chown -R "${REMAP_UID}:${REMAP_GID}" "${FS_ROOT}"

echo ""
echo "[fs-scaffold] DONE. Fake filesystem created at ${FS_ROOT}"
echo ""
echo "Contents:"
find "${FS_ROOT}" -type f | sort | sed 's|'"${FS_ROOT}"'|  <fs_root>|'
echo ""
echo "Next steps:"
echo "  1. cp cowrie.cfg.example ../../config/cowrie/cowrie.cfg"
echo "  2. echo 'root:*' > ../../config/cowrie/userdb.txt"
echo "  3. chown 100000:100000 ../../config/cowrie/cowrie.cfg ../../config/cowrie/userdb.txt"
echo "  4. docker compose up -d"
echo "  5. bash verify-module-2.sh"
