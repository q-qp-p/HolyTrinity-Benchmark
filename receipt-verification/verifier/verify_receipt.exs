#!/usr/bin/env elixir
#
# verify_receipt.exs — check a Trinity authority receipt's Ed25519 signature.
#
#   elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json
#
# No Mix project, no hex packages, no network. Requires Elixir 1.17 / OTP 27 or later for the
# built-in `:json` module; verified on Elixir 1.19.2 / OTP 28.
#
# EXIT CODES — see README.md. `5` is shared with the VIRP verifier; the others are this project's
# proposal and are PROVISIONAL pending reconciliation of the two vocabularies.
#
#   0  verified                 the signature is good under an independently supplied key
#   1  signature invalid        THE RECEIPT IS BAD — content and signature disagree
#   2  usage error              says nothing about the receipt
#   5  trust not established    THE RECEIPT IS UNJUDGED — no independent basis to check it against
#   6  key compromised          signature valid, signer trust degraded (PROVISIONAL CODE)
#
# `1` and `5` are deliberately different. `1` means the receipt is bad. `5` means we were not given
# what we would need to judge it. Reporting the second as the first tells an examiner a receipt was
# forged when it was merely unverifiable as presented.
#
# PATTERN CREDIT — the default-distrust posture, the refusal when signer trust is not established
# from bundle-local key material, and the discipline of disclosing flaws unprompted are taken from:
#
#   Nathan Howard (Third Level IT / thirdlevel.ai)
#   VIRP verifier, v0.1.0
#   https://github.com/nhowardtli/virp/releases/tag/v0.1.0-verifier
#
# THIS VERIFIER IS OUR ARTIFACT. An examiner who distrusts us has no reason to trust it either.
# It is short and dependency-free so it can be read in full, the signing scheme is specified in
# README.md so it can be reimplemented from scratch, and a second independent implementation ships
# beside it (verify_receipt.py, Python standard library only). Two implementations agreeing is a
# stronger basis than either alone.

defmodule VerifyReceipt do
  @exit_verified 0
  @exit_invalid 1
  @exit_usage 2
  @exit_no_trust 5
  @exit_compromised 6

  def main(argv) do
    case parse(argv) do
      {:ok, receipt_path, registry_path} -> run(receipt_path, registry_path)
      {:error, message} -> fail(@exit_usage, message)
    end
  end

  defp parse(argv) do
    opts =
      argv
      |> Enum.chunk_every(2)
      |> Enum.reduce(%{}, fn
        ["--receipt", value], acc -> Map.put(acc, :receipt, value)
        ["--registry", value], acc -> Map.put(acc, :registry, value)
        _other, acc -> acc
      end)

    cond do
      is_nil(opts[:receipt]) ->
        {:error, "usage: verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json"}

      # DEFAULT DISTRUST. Absent an independently supplied registry there is no basis to judge the
      # receipt, and inventing one from the bundle is the failure this whole scheme exists to
      # remove. This is a refusal, not a verdict — hence 5, not 1.
      is_nil(opts[:registry]) ->
        {:error, :no_registry}

      true ->
        {:ok, opts[:receipt], opts[:registry]}
    end
  end

  defp run(receipt_path, registry_path) do
    with {:ok, receipt} <- read_json(receipt_path),
         {:ok, registry} <- read_json(registry_path) do
      verify(receipt, registry)
    else
      {:error, message} -> fail(@exit_usage, message)
    end
  end

  defp verify(receipt, registry) do
    payload = receipt["signed_payload"]
    signature = receipt["signature"]
    key_id = receipt["key_id"]

    cond do
      not is_binary(payload) or not is_binary(signature) or not is_binary(key_id) ->
        fail(@exit_usage, "receipt must carry signed_payload, signature and key_id")

      true ->
        note_ignored_key(receipt)
        entry = find_entry(registry, key_id)
        check(entry, key_id, payload, signature, receipt)
    end
  end

  # The receipt may carry a public_key. It is NEVER used. A verifier that reads the key out of the
  # thing it is checking is checking a signature against a key the same party supplied, which
  # establishes nothing — it is the symmetric scheme wearing asymmetric clothes.
  defp note_ignored_key(receipt) do
    if is_binary(receipt["public_key"]) do
      IO.puts("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")
    end
  end

  defp find_entry(registry, key_id) do
    (registry["entries"] || []) |> Enum.find(fn entry -> entry["key_id"] == key_id end)
  end

  defp check(nil, key_id, _payload, _signature, _receipt) do
    fail(@exit_no_trust, """
    TRUST NOT ESTABLISHED — the registry does not name key_id #{inspect(key_id)}.

    This is not a statement that the receipt is bad. It is a statement that the registry you
    supplied gives no basis to judge it. Obtain the registry that names this key, from a channel
    independent of the receipt, and run again. The verifier does not fall back to any other key.
    """)
  end

  defp check(%{"status" => "example"}, key_id, _payload, _signature, _receipt) do
    fail(@exit_no_trust, """
    TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} is an example key, not a trust root.

    Example entries exist to demonstrate the registry's schema. They are generated from a published
    string, so their private half is not secret and anything they sign proves nothing.
    """)
  end

  defp check(entry, key_id, payload, signature, receipt) do
    with :ok <- check_hash(receipt, payload),
         :ok <- check_signature(payload, signature, entry["public_key"]) do
      case entry["status"] do
        "compromised" -> compromised(key_id, entry)
        _active_or_retired -> verified(key_id, entry)
      end
    else
      {:error, code, message} -> fail(code, message)
    end
  end

  defp check_hash(receipt, payload) do
    case receipt["receipt_hash"] do
      hash when is_binary(hash) ->
        actual = :crypto.hash(:sha256, payload) |> Base.encode16(case: :lower)

        if actual == hash,
          do: :ok,
          else:
            {:error, @exit_invalid,
             "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes."}

      _absent ->
        :ok
    end
  end

  defp check_signature(payload, signature, public_key) do
    with {:ok, raw_signature} <- Base.decode64(signature),
         {:ok, raw_key} <- Base.decode64(public_key || ""),
         true <- :crypto.verify(:eddsa, :none, payload, raw_signature, [raw_key, :ed25519]) do
      :ok
    else
      _otherwise ->
        {:error, @exit_invalid,
         "SIGNATURE INVALID — the signature does not check out against the registry's public key."}
    end
  rescue
    ErlangError ->
      {:error, @exit_invalid, "SIGNATURE INVALID — malformed signature or key material."}
  end

  defp verified(key_id, entry) do
    IO.puts("""
    VERIFIED — signature is valid under key_id #{inspect(key_id)} (status: #{entry["status"]}).

    A retired key verifies exactly like an active one. Rotation does not invalidate receipts already
    issued; only new signing stops.

    Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so a
    valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content.
    """)

    System.halt(@exit_verified)
  end

  defp compromised(key_id, entry) do
    IO.puts("""
    KEY COMPROMISED — the signature is cryptographically valid under key_id #{inspect(key_id)}, but
    the registry marks that key compromised as of #{entry["status_changed_at"]}.

    WHAT THIS VERDICT CAN AND CANNOT ESTABLISH, stated here rather than left to be discovered:

      * The signature is genuine in the sense that it checks out against the published key.
      * It does NOT establish that the issuer produced it. Anyone holding the compromised private
        key could have.
      * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on knowing
        when it was signed — and the signing time is asserted by the receipt itself, which an
        adversary holding that key can backdate.

    So this verdict is sound for honest history and advisory against a forger. Closing that gap
    requires anchoring signing times outside the issuing system; it is named future work, not a
    solved problem.

    Exit code 6 is PROVISIONAL, pending reconciliation with the VIRP vocabulary.
    """)

    System.halt(@exit_compromised)
  end

  defp read_json(path) do
    case File.read(path) do
      {:ok, raw} ->
        try do
          {:ok, :json.decode(raw)}
        rescue
          _error -> {:error, "#{path} is not valid JSON"}
        end

      {:error, reason} ->
        {:error, "cannot read #{path}: #{:file.format_error(reason)}"}
    end
  end

  defp fail(_code, :no_registry) do
    IO.puts(:stderr, """
    TRUST NOT ESTABLISHED — no --registry was supplied.

    This verifier refuses to check a signature against key material that arrived with the receipt.
    A key obtained from the same download as the evidence proves nothing: whoever produced the
    bundle chose both halves.

    Supply a registry you obtained INDEPENDENTLY of this receipt:

        elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json

    The registry is published in the public repository, where every append is a dated commit you
    can walk and tampering is detectable against any older clone.

    A second channel — a Zenodo deposit carrying a DOI — is INTENDED and NOT YET LIVE. When it
    exists you will be able to cross-check one against the other, and disagreement between them
    will itself be an alarm. Until then there is one channel, and this tool says so rather than
    implying a check you cannot perform.
    """)

    System.halt(@exit_no_trust)
  end

  defp fail(code, message) do
    IO.puts(:stderr, message)
    System.halt(code)
  end
end

VerifyReceipt.main(System.argv())
