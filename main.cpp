/*
    Authors: Kacper Nowak, Jakub Ziółkowski
    For cryptographic purposes a Crypto++ library was used (https://github.com/weidai11/cryptopp). 
*/

#include <cryptopp/des.h>
#include <iostream>
#include <thread>
#include <random>

//! A size in bytes of a single block to process in encyption/decryption operation. Note that the data will be divided into sizeof(data)/block_size blocks.
#define BLOCK_SIZE 32
//! A size of a CryptoPP::byte* data block holding both plaintext and ciphertext.
#define MESSAGE_SIZE 1024
//! Hard-coded message to encrypt. It is used to validate the decryption output in brute-force method.
#define HIDDEN_MESSAGE "ODGADNIJ MNIE UKRYTA WIADOMOSC"

std::mutex mutx;
//! A variable storing the ciphertext. Is used by threads as an argument for DES_process function.
CryptoPP::byte* textBlock;

//! Char array holding initial, hard-coded password (initially), and then used by threads in BF process (incrementation step-by-step after all possibilities are generated.)
char password[8]{ CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, 2, 0 };
//! this boolean notify the program that the password has been broken - no more threads are spawned, and the program exits.
bool success = false;
//! this boolean notify the program that all keys were generated (which should take a lot of time).
bool generatedAll = false;

//! A function which encrypts/decrypts CryptoPP::byte* data type.
/*!
    This function operates on inputBlock using the key passed, and stores the output in outputBlock. Note that it uses memcpy() for e.g. key copy, which means exactly 64 bites of a key are copied and than processed.
    Data passed is processed in blocks of a size of length parameter.

    \param keyString a constant argument, used as a password. Please notice that due to DES specification only 64 bites will be copied; however the keyString length is not limited.
    \param inputBlock a constant data block used as a source for encryption/decryption.
    \param outputBlock a data block which will be modified and containts the result of encrypt./decryption operation.
    \param length a size of a single block which will be processed. The inputBlock/outputBlock will be diveded into segments of this length.
    \param direction an argument used for setting the operation type (encryption/decryption).
    \return Nothing - as result of operation is stored in outputBlock.
*/
void DES_Process(const char* keyString, const CryptoPP::byte* inputBlock, CryptoPP::byte* outputBlock, size_t length, CryptoPP::CipherDir direction){
    using namespace CryptoPP;
    byte key[DES::KEYLENGTH];
    memcpy(key, keyString, DES::KEYLENGTH);

    std::unique_ptr<BlockTransformation> t;
    if(direction == ENCRYPTION)
        t = std::make_unique<DESEncryption>(key, DES::KEYLENGTH);
    else
        t = std::make_unique<DESDecryption>(key, DES::KEYLENGTH);

    memcpy(outputBlock, inputBlock, MESSAGE_SIZE);

    int steps = length / t->BlockSize();
    for(int i=0; i<steps; i++){
        int offset = i * t->BlockSize();
        t->ProcessBlock(outputBlock + offset);
    }
}
//! A function which incremenets the char array by 1, i.e. 0 255 255 -> 1 0 0.
/*!
    This function also writes to stdout the current key (before incrementation).
    It may set the generatedAll flag - if all combinations were generated (the key is 255 255 ... 255).
*/
void incrementPassword()
{
    for(int i=0;i<CryptoPP::DES::KEYLENGTH;i++)
    {
        std::cout << static_cast<int>(password[i]) << " ";
    }
    std::cout << std::endl;
    int i  = CryptoPP::DES::KEYLENGTH-1;
    while(password[i]==CHAR_MAX && i>=0)
    {
        password[i] = CHAR_MIN;
        i--;
    }
    if(i==0 && password[i]==CHAR_MAX)
    {
        generatedAll = true;
        return;
    }
    else
    {
        password[i] = password[i]+1;
        return;
    }
}

//! A function used for thread initialization.
/*!
    It increments the password (thread-safe), tries to decrypt the message and compare the outcome with HIDDEN_MESSAGE macro.
    It may set the success flag if a stcmp operation returns 0.
*/
void thread_function()
{
    mutx.lock();
    incrementPassword();
    mutx.unlock();
    auto candidate = new CryptoPP::byte[MESSAGE_SIZE];
    DES_Process(password, textBlock, candidate, BLOCK_SIZE, CryptoPP::DECRYPTION);
    if(strcmp(reinterpret_cast<const char*>(candidate), HIDDEN_MESSAGE)==0)
    {
        mutx.lock();
        success = true;
        std::cout << "DES was successfully broken. Decipher text: " << candidate << std::endl;
        mutx.unlock();
    }
    delete[] candidate;
}
//! A global array used for storing std::threads; which are spawned in a loop until any of boolean flags are set.
std::vector<std::thread> threadPool;
int main(int argc, char *argv[])
{
    textBlock = new CryptoPP::byte[MESSAGE_SIZE];
    memcpy(textBlock, HIDDEN_MESSAGE, MESSAGE_SIZE);
    DES_Process(password, textBlock, textBlock, BLOCK_SIZE, CryptoPP::ENCRYPTION);
    for(int i=0;i<CryptoPP::DES::KEYLENGTH;i++)
        password[i] = CHAR_MIN;
    int i = 0;
    while(!success && !generatedAll)
    {
        threadPool.push_back(std::thread(&thread_function));
        threadPool.at(i++).join();
    }
    delete[] textBlock;
    return 0;
}