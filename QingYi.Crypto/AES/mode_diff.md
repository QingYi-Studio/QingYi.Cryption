# Mode diff

1. **ECB (Electronic Codebook) Mode**:
   - **Operation**: Encrypts each block of plaintext independently.
   - **操作**：对每个明文块独立加密。
   - **Pros**: Simple to implement and fast.
   - **优点**：实现简单，速度较快。
   - **Cons**: Identical plaintext blocks produce identical ciphertext blocks, which can reveal data patterns and is less secure.
   - **缺点**：相同的明文块会产生相同的密文块，可能暴露数据模式，安全性较差。

2. **CBC (Cipher Block Chaining) Mode**:
   - **Operation**: Each plaintext block is XORed with the previous ciphertext block (or with an initialization vector (IV) for the first block) before encryption.
   - **操作**：每个明文块在加密前与前一个密文块（第一个块与初始化向量IV）进行异或操作。
   - **Pros**: Provides higher security compared to ECB by ensuring that identical plaintext blocks will produce different ciphertext blocks.
   - **优点**：比ECB模式提供更高的安全性，因为相同的明文块会因为前一个块的影响而产生不同的密文块。
   - **Cons**: Requires careful management of the IV and is less suitable for parallel processing.
   - **缺点**：需要仔细管理IV，不适合并行处理。

3. **OFB (Output Feedback) Mode**:
   - **Operation**: Generates a pseudorandom stream from the encryption algorithm, which is then XORed with the plaintext to produce ciphertext.
   - **操作**：从加密算法生成伪随机流，然后与明文进行异或得到密文。
   - **Pros**: Can perform stream encryption, making it suitable for encrypting data streams.
   - **优点**：可以进行流加密，适用于加密数据流。
   - **Cons**: IV must be unique. The generated pseudorandom stream will differ as long as the IV is different, even if the key remains the same.
   - **缺点**：IV必须唯一。只要IV不同，生成的伪随机流也会不同，即使密钥相同。

4. **CFB (Cipher Feedback) Mode**:
   - **Operation**: Similar to OFB, but the output from the encryption algorithm is fed back as input for subsequent encryption operations.
   - **操作**：类似于OFB模式，但加密算法的输出作为输入反馈用于后续的加密操作。
   - **Pros**: Supports stream encryption and is useful for real-time data encryption.
   - **优点**：支持流加密，适用于实时数据加密。
   - **Cons**: More complex to implement due to the feedback mechanism, and errors can propagate if not handled correctly.
   - **缺点**：由于反馈机制，实施更复杂，错误可能会传播，如果处理不当可能会引入问题。

5. **CTS (Cipher Text Stealing) Mode**:
   - **Operation**: Often used with CBC mode to handle cases where the plaintext length is not a multiple of the block size.
   - **操作**：通常与CBC模式结合使用，处理明文长度不是块大小的整数倍的情况。
   - **Pros**: Suitable for cases where precise control over data length is required without additional padding.
   - **优点**：适合需要精确控制数据长度而不需要额外填充的情况。
   - **Cons**: More complex to implement, especially in managing the last block of data.
   - **缺点**：实现更复杂，尤其是在处理最后一个数据块时。