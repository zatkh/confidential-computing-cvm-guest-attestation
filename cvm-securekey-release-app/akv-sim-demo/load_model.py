#!/usr/bin/env python3
"""
Load the (decrypted) Phi-4-mini model onto the confidential GPU and run a short
generation, proving the released-and-decrypted weights are usable.

Run AFTER model_crypto.py decrypt has restored the *.safetensors files.
"""

import argparse
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description="Load + run the decrypted model.")
    parser.add_argument("--model-dir", required=True,
                        help="Directory with decrypted *.safetensors + config.")
    parser.add_argument("--prompt", default="Explain confidential GPU computing in one sentence.")
    parser.add_argument("--max-new-tokens", type=int, default=64)
    parser.add_argument("--device", default="cuda",
                        help="cuda | cpu (default: cuda).")
    args = parser.parse_args(argv)

    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        sys.stderr.write(
            "ERROR: install model deps: pip install -r requirements-model.txt\n")
        return 2

    print(f"[load] loading tokenizer + model from {args.model_dir} ...")
    tok = AutoTokenizer.from_pretrained(args.model_dir, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        args.model_dir,
        torch_dtype=torch.bfloat16 if args.device == "cuda" else torch.float32,
        device_map=args.device if args.device == "cuda" else None,
        trust_remote_code=True,
    )
    if args.device != "cuda":
        model = model.to(args.device)

    if args.device == "cuda" and torch.cuda.is_available():
        print(f"[load] GPU: {torch.cuda.get_device_name(0)}")

    msgs = [{"role": "user", "content": args.prompt}]
    try:
        inputs = tok.apply_chat_template(
            msgs, add_generation_prompt=True, return_tensors="pt").to(model.device)
    except Exception:
        inputs = tok(args.prompt, return_tensors="pt").input_ids.to(model.device)

    print(f"[run]  prompt: {args.prompt}")
    out = model.generate(inputs, max_new_tokens=args.max_new_tokens,
                         do_sample=False)
    text = tok.decode(out[0][inputs.shape[-1]:], skip_special_tokens=True)
    print("[run]  output:")
    print(text.strip())
    print("\n[ok] Decrypted Phi-4-mini ran on the confidential GPU.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
