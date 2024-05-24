defmodule Paseto.Crypto.XChaCha20Poly1305 do
  @moduledoc """
  Implement XChaCha20Poly1305 encryption and decryption.
  """

  @spec encrypt(binary(), binary(), binary(), binary()) :: {:ok, binary()}
  def encrypt(message, aad, <<iv::192-bits>>, <<key::256-bits>>) do
    # Perform the HChaCha20 operation to generate the subkey and nonce
    {subkey, nonce} = xchacha20_subkey_and_nonce(key, iv)

    # Perform the ChaCha20 operation to encrypt the message
    block_encrypt(subkey, nonce, {aad, message})
  end

  @spec decrypt(binary(), binary(), binary(), binary()) :: {:ok, binary()}
  def decrypt(encrypted, aad, <<iv::192-bits>>, <<key::256-bits>>) do
    cipher_text_size = byte_size(encrypted) - 16
    <<cipher_text::bytes-size(cipher_text_size), cipher_tag::128-bits>> = encrypted

    # Perform the HChaCha20 operation to generate the subkey and nonce
    {subkey, nonce} = xchacha20_subkey_and_nonce(key, iv)

    # Perform the ChaCha20 operation to decrypt the message
    block_decrypt(:chacha20_poly1305, subkey, nonce, {aad, cipher_text, cipher_tag})
  end

  defp xchacha20_subkey_and_nonce(key, <<nonce0::128-bits, nonce1::64-bits>>) do
    subkey = hchacha20(key, nonce0)
    nonce = <<0::32, nonce1::64-bits>>
    {subkey, nonce}
  end

  defp hchacha20(key, nonce) do
    # ChaCha20 has an internal blocksize of 512-bits (64-bytes).
    # Let's use a Mask of random 64-bytes to blind the intermediate keystream.
    mask = <<mask_h::128-bits, _::256-bits, mask_t::128-bits>> = :crypto.strong_rand_bytes(64)

    <<state_2h::128-bits, _::256-bits, state_2t::128-bits>> =
      :crypto.crypto_one_time(:chacha20, key, nonce, mask, true)

    <<
      x00::32-unsigned-little-integer,
      x01::32-unsigned-little-integer,
      x02::32-unsigned-little-integer,
      x03::32-unsigned-little-integer,
      x12::32-unsigned-little-integer,
      x13::32-unsigned-little-integer,
      x14::32-unsigned-little-integer,
      x15::32-unsigned-little-integer
    >> =
      :crypto.exor(
        <<mask_h::128-bits, mask_t::128-bits>>,
        <<state_2h::128-bits, state_2t::128-bits>>
      )

    ## The final step of ChaCha20 is `State2 = State0 + State1', so let's
    ## recover `State1' with subtraction: `State1 = State2 - State0'
    <<
      y00::32-unsigned-little-integer,
      y01::32-unsigned-little-integer,
      y02::32-unsigned-little-integer,
      y03::32-unsigned-little-integer,
      y12::32-unsigned-little-integer,
      y13::32-unsigned-little-integer,
      y14::32-unsigned-little-integer,
      y15::32-unsigned-little-integer
    >> = <<"expand 32-byte k", nonce::128-bits>>

    <<
      x00 - y00::32-unsigned-little-integer,
      x01 - y01::32-unsigned-little-integer,
      x02 - y02::32-unsigned-little-integer,
      x03 - y03::32-unsigned-little-integer,
      x12 - y12::32-unsigned-little-integer,
      x13 - y13::32-unsigned-little-integer,
      x14 - y14::32-unsigned-little-integer,
      x15 - y15::32-unsigned-little-integer
    >>
  end

  defp block_encrypt(key, iv, {aad, payload}) do
    {cipher_text, cipher_tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, payload, aad, true)

    {:ok, cipher_text <> cipher_tag}
  catch
    :error, :notsup -> raise_notsup()
  end

  defp block_decrypt(cipher, key, iv, {aad, payload, tag}) do
    plain = :crypto.crypto_one_time_aead(cipher, key, iv, payload, aad, tag, false)
    {:ok, plain}
  catch
    :error, :notsup -> raise_notsup()
  end

  defp raise_notsup do
    raise "The algorithm chacha20_poly1305 is not supported by your Erlang/OTP installation. " <>
            "Please make sure it was compiled with the correct OpenSSL/BoringSSL bindings"
  end
end
