#!/usr/bin/env elixir
#
# verify_receipt.exs — check a Trinity authority receipt's Ed25519 signature.
#
#   elixir verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json
#
# No Mix project, no hex packages, no network. Requires Elixir 1.17 / OTP 27 or later for the
# built-in `:json` module; verified on Elixir 1.19.2 / OTP 28.
#
# EXIT CODES AND EVERY VERDICT CASE ARE DEFINED IN ONE PLACE: VERDICTS.md, beside this file. It is
# the single source, it is parsed by the cross-check test, and this header cites it rather than
# restating it. Four copies of one rule is how the copies drift.
#
# The numbers are frozen at 0, 1, 2, 5, 6 and no others may be introduced. `5` is shared with the
# VIRP verifier; the rest are this project's proposal and are PROVISIONAL. The one distinction to
# carry in your head while reading: `1` accuses the receipt, `5` declines to judge it, and
# collapsing them tells an examiner a receipt was forged when it was merely unverifiable.
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
# stronger basis than either alone. They share NO code, on purpose.

defmodule VerifyReceipt do
  @exit_verified 0
  @exit_invalid 1
  @exit_usage 2
  @exit_no_trust 5
  @exit_compromised 6

  @statuses ~w(example active retired compromised)
  @envelope ~w(signature key_id signed_payload receipt_hash)
  @ignored ~w(public_key _note)
  @timestamp ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

  def main(argv) do
    case parse(argv, %{}) do
      {:ok, receipt_path, registry_path} -> run(receipt_path, registry_path)
      {:error, message} -> fail(@exit_usage, message)
      {:no_registry} -> fail(@exit_no_trust, :no_registry)
    end
  end

  # Scanned explicitly rather than chunked, so `--receipt` with no value after it is a USAGE error
  # and never a silently dropped flag that changes the verdict.
  defp parse([flag], _opts) when flag in ["--receipt", "--registry"],
    do: {:error, "usage: #{flag} requires a value"}

  defp parse([flag, value | rest], opts) when flag in ["--receipt", "--registry"],
    do: parse(rest, Map.put(opts, flag, value))

  defp parse([_ignored | rest], opts), do: parse(rest, opts)

  defp parse([], opts) do
    cond do
      is_nil(opts["--receipt"]) ->
        {:error, "usage: verify_receipt.exs --receipt RECEIPT.json --registry REGISTRY.json"}

      # DEFAULT DISTRUST. Absent an independently supplied registry there is no basis to judge the
      # receipt, and inventing one from the bundle is the failure this scheme exists to remove.
      is_nil(opts["--registry"]) ->
        {:no_registry}

      true ->
        {:ok, opts["--receipt"], opts["--registry"]}
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

  defp verify(receipt, registry) when is_map(receipt) do
    payload = receipt["signed_payload"]
    signature = receipt["signature"]
    key_id = receipt["key_id"]

    if not (is_binary(payload) and is_binary(signature) and is_binary(key_id)) do
      fail(@exit_usage, "receipt must carry signed_payload, signature and key_id")
    end

    note_ignored_key(receipt)

    # ORDER IS VERDICTS.md's. Every trust question precedes every accusation, because an
    # accusation requires standing.
    entry = trusted_entry(registry, key_id)
    signed = signed_object(payload)
    occurred = occurred_at(signed)
    {valid_from, valid_to} = window(entry, key_id)

    check_hash(receipt, payload)
    check_siblings(receipt, signed)
    raw_key = check_signature(payload, signature, entry)
    _ = raw_key

    if entry["status"] == "compromised", do: compromised(key_id, entry)

    check_window(occurred, valid_from, valid_to, key_id, entry, signed)

    verified(key_id, entry)
  end

  defp verify(_receipt, _registry), do: fail(@exit_usage, "the receipt must be a JSON object")

  # The receipt may carry a public_key. It is NEVER used. A verifier that reads the key out of the
  # thing it is checking establishes nothing — it is the symmetric scheme wearing asymmetric
  # clothes.
  defp note_ignored_key(receipt) do
    if is_binary(receipt["public_key"]) do
      IO.puts("note: the receipt carries a public_key; it is ignored. Trust comes from --registry.")
    end
  end

  defp trusted_entry(registry, key_id) do
    entries = Enum.filter(registry["entries"] || [], &(is_map(&1) and &1["key_id"] == key_id))

    case entries do
      [] ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — the registry does not name key_id #{inspect(key_id)}.

        This is not a statement that the receipt is bad. It is a statement that the registry you
        supplied gives no basis to judge it. The verifier does not fall back to any other key.
        """)

      # V-DUPKEY. Taking the first would let DOCUMENT ORDER select the verdict, inside a file whose
      # governing rule is that entries are never removed or rewritten.
      [_first, _second | _rest] ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — the registry names key_id #{inspect(key_id)} #{length(entries)} times.

        The registry is append-only: an entry is never removed and never rewritten, so one key_id
        names one key. Two entries mean the file is internally inconsistent, and picking either one
        would let the ORDER of a document decide the verdict.

        Detected on key_id only. Two entries sharing a public key under DIFFERENT key_ids is not
        this error.
        """)

      [only] ->
        check_status(only, key_id)
        check_fingerprint(only, key_id)
        only
    end
  end

  # DEFAULT DENY. The registry defines exactly four statuses. A status this verifier cannot
  # interpret is a reason to refuse, never to pass.
  defp check_status(entry, key_id) do
    status = entry["status"]

    cond do
      is_binary(status) and status == "example" ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} is an example key, not a trust root.

        Example entries exist to demonstrate the registry's schema. They are generated from a
        published string, so their private half is not secret and anything they sign proves nothing.
        """)

      is_binary(status) and status in @statuses ->
        :ok

      true ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} carries status #{inspect(status)}.

        The registry defines exactly four: example, active, retired, compromised. A status outside
        that set, or absent, is standing this verifier cannot interpret. It refuses rather than
        treating the unrecognised as the benign.
        """)
    end
  end

  # The entry must hash to its own published fingerprint BEFORE anything it says is believed,
  # including its status and its window. An entry failing its own integrity check may have been
  # substituted.
  defp check_fingerprint(entry, key_id) do
    stated = entry["public_key_fingerprint"]

    with {:ok, raw} <- decode64(entry["public_key"]),
         true <- is_binary(stated),
         true <- Base.encode16(:crypto.hash(:sha256, raw), case: :lower) == stated do
      :ok
    else
      _otherwise ->
        fail(@exit_no_trust, """
        TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} does not hash to its own published fingerprint.

        public_key_fingerprint is sha256 over the RAW key bytes, lowercase hex. This entry fails its
        own integrity check, so nothing it states — its status, its window, its key — can be relied
        on.
        """)
    end
  end

  defp window(entry, key_id) do
    from = timestamp(entry["valid_from"])
    to_raw = entry["valid_to"]

    if is_nil(from) do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} has no usable valid_from.

      Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly. A window that cannot be read cannot place a
      receipt inside or outside it.
      """)
    end

    # `:json.decode/1` renders JSON null as the ATOM :null, not nil. Both mean "no upper bound",
    # and conflating only one of them would read an open-ended window as an unreadable one.
    to =
      if to_raw in [nil, :null] do
        nil
      else
        case timestamp(to_raw) do
          nil ->
            fail(@exit_no_trust, """
            TRUST NOT ESTABLISHED — key_id #{inspect(key_id)} has an unreadable valid_to.

            Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly, or null for a key still signing.
            """)

          value ->
            value
        end
      end

    {from, to}
  end

  defp signed_object(payload) do
    try do
      case :json.decode(payload) do
        decoded when is_map(decoded) -> decoded
        _other -> nil
      end
    rescue
      _error -> nil
    end
  end

  defp occurred_at(signed) do
    value = if is_map(signed), do: timestamp(signed["occurred_at"]), else: nil

    if is_nil(value) do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — the signed bytes carry no readable occurred_at.

      occurred_at is the only signing time a receipt carries, and it is what the key's signing
      window is checked against. Accepted form is YYYY-MM-DDTHH:MM:SSZ exactly; it is refused
      rather than coerced, so the two implementations cannot drift.
      """)
    end

    value
  end

  # Fixed width, zero padded, most significant field first, one literal UTC suffix. Within that
  # accepted set, and ONLY within it, byte order is chronological order — which is why the regex is
  # not decoration but the precondition that makes the comparison correct.
  defp timestamp(value) when is_binary(value) do
    if Regex.match?(@timestamp, value), do: value, else: nil
  end

  defp timestamp(_value), do: nil

  defp check_hash(receipt, payload) do
    case receipt["receipt_hash"] do
      hash when is_binary(hash) ->
        actual = :crypto.hash(:sha256, payload) |> Base.encode16(case: :lower)

        if actual != hash do
          fail(
            @exit_invalid,
            "SIGNATURE INVALID — the receipt's own receipt_hash does not match its signed bytes."
          )
        end

      _absent ->
        fail(@exit_invalid, """
        SIGNATURE INVALID — the receipt carries no receipt_hash.

        A receipt states the digest of its own signed bytes. An absent field is not a check to be
        skipped; it is a receipt that declines to be held to anything.
        """)
    end
  end

  # Any top-level field that also appears inside the signed bytes must agree with it. A reader takes
  # the visible field for part of the receipt, and the signature covers only the signed bytes.
  defp check_siblings(receipt, signed) when is_map(signed) do
    Enum.each(receipt, fn {key, value} ->
      cond do
        key in @envelope or key in @ignored -> :ok
        not Map.has_key?(signed, key) -> :ok
        tagged(value) == tagged(signed[key]) -> :ok
        true ->
          fail(@exit_invalid, """
          SIGNATURE INVALID — the receipt displays #{inspect(key)} as #{inspect(value)}, but the
          SIGNED bytes say #{inspect(signed[key])}.

          A reader takes the visible field for part of the receipt. The signature covers only the
          signed bytes, so a top-level field contradicting them is a claim no signature stands
          behind.
          """)
      end
    end)
  end

  defp check_siblings(_receipt, _signed), do: :ok

  # Type-tagged, so equality never merges an integer with a float or a boolean with 1. The canonical
  # encoding never merges those; a bare `==` in either language does, on exactly the values an
  # adversary would choose.
  defp tagged(value) when is_boolean(value), do: {:bool, value}
  defp tagged(value) when is_integer(value), do: {:int, value}
  defp tagged(value) when is_float(value), do: {:float, value}
  defp tagged(value) when is_binary(value), do: {:str, value}
  defp tagged(value) when value in [nil, :null], do: {:null}
  defp tagged(value) when is_list(value), do: {:list, Enum.map(value, &tagged/1)}

  defp tagged(value) when is_map(value),
    do: {:object, value |> Enum.map(fn {k, v} -> {k, tagged(v)} end) |> Enum.sort()}

  defp tagged(value), do: {:other, inspect(value)}

  defp check_signature(payload, signature, entry) do
    with {:ok, raw_signature} <- decode64(signature),
         {:ok, raw_key} <- decode64(entry["public_key"]),
         true <- :crypto.verify(:eddsa, :none, payload, raw_signature, [raw_key, :ed25519]) do
      raw_key
    else
      _otherwise ->
        fail(
          @exit_invalid,
          "SIGNATURE INVALID — the signature does not check out against the registry's public key."
        )
    end
  rescue
    ErlangError ->
      fail(@exit_invalid, "SIGNATURE INVALID — malformed signature or key material.")
  end

  # Half-open: valid_from <= occurred_at < valid_to. VERDICTS.md records why the published
  # registries settle that convention rather than taste.
  defp check_window(occurred, from, to, key_id, entry, signed) do
    outside = occurred < from or (not is_nil(to) and occurred >= to)

    if outside do
      fail(@exit_no_trust, """
      TRUST NOT ESTABLISHED — the receipt says it was signed at #{signed["occurred_at"]}, outside
      key_id #{inspect(key_id)}'s signing window [#{entry["valid_from"]}, #{entry["valid_to"]}).

      A retired key's signatures survive its retirement; a signature dated after the window closed
      was never covered by that rule. The window is half-open, so an occurred_at equal to valid_to
      is outside it.

      Sound for honest history, advisory against a forger: occurred_at is asserted by the receipt,
      and an adversary holding the key can backdate it.
      """)
    end
  end

  defp decode64(value) when is_binary(value), do: Base.decode64(value)
  defp decode64(_value), do: :error

  defp verified(key_id, entry) do
    IO.puts("""
    VERIFIED — signature is valid under key_id #{inspect(key_id)} (status: #{entry["status"]}).

    A retired key verifies exactly like an active one WITHIN ITS SIGNING WINDOW. Rotation does not
    invalidate receipts already issued; only new signing stops.

    Note what this attests: the signed bytes carry the receipt's sequence and previous_hash, so a
    valid signature binds the receipt's POSITION IN ITS CHAIN as well as its content.
    """)

    System.halt(@exit_verified)
  end

  # 6 asserts the signature IS cryptographically valid, so it is never reached over a failed
  # verification. It sits after the receipt checks for that reason and not by accident.
  defp compromised(key_id, entry) do
    IO.puts("""
    KEY COMPROMISED — the signature is cryptographically valid under key_id #{inspect(key_id)}, but
    the registry marks that key compromised as of #{entry["status_changed_at"]}.

    WHAT THIS VERDICT CAN AND CANNOT ESTABLISH:

      * The signature checks out against the published key.
      * It does NOT establish that the issuer produced it. Anyone holding the compromised private
        key could have.
      * Separating a receipt signed BEFORE the compromise from one signed AFTER depends on the
        signing time, which the receipt asserts about itself and an adversary holding that key can
        backdate.

    Sound for honest history, advisory against a forger. Closing the gap requires anchoring signing
    times outside the issuing system; that is named future work.

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
