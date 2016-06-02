/**
 * Copyright IBM Corporation 2016
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Cryptor

let key = CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
let iv = CryptoUtils.byteArray(fromHex: "00000000000000000000000000000000")
let plainText = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a")
print("Plaintext  = " + CryptoUtils.hexString(from: plainText))

var textToCipher = plainText
if plainText.count % Cryptor.Algorithm.aes.blockSize != 0 {
    textToCipher = CryptoUtils.zeroPad(byteArray: plainText, blockSize: Cryptor.Algorithm.aes.blockSize)
}
let cipherText = Cryptor(operation: .encrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: textToCipher)?.final()
print("Ciphertext = " + CryptoUtils.hexString(from: cipherText!))

let decryptedText = Cryptor(operation: .decrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: cipherText!)?.final()
print("Decrypted  = " + CryptoUtils.hexString(from: decryptedText!))

