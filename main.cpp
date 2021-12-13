#include <cryptopp/des.h>
#include <iostream>
#include <thread>
#include <random>

#define BLOCK_SIZE 32
#define MESSAGE_SIZE 1024
#define HIDDEN_MESSAGE "ODGADNIJ MNIE UKRYTA WIADOMOSC"

std::mutex mutx;
CryptoPP::byte* textBlock;

char password[8]{ CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, CHAR_MIN, 2, 0 };
bool success = false;
bool generatedAll = false;

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