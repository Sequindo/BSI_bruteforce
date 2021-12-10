#include <cryptopp/des.h>
#include <iostream>
#include <thread>

#define BLOCK_SIZE 32

std::mutex mutx;
char password[8]{0};
CryptoPP::byte plaintext[] = {218, 15, 32, 166, 4, 32, 217, 165, 210, 229, 32, 133, 32, 207, 182, 255, 190, 32, 205, 161, 32, 3, 201, 245, 214, 137, 215, 154, 32, 168, 235};
bool areAllCombinationsGenerated = false;
bool success = false;

char* DES_Process(const char* keyString, const CryptoPP::byte* block, size_t length, CryptoPP::CipherDir direction){
    using namespace CryptoPP;

    byte key[DES_EDE2::KEYLENGTH];
    memcpy(key, keyString, DES_EDE2::KEYLENGTH);

    byte* modifiedText;
    memcpy(modifiedText, block, sizeof(block));

    std::unique_ptr<BlockTransformation> t;
    if(direction == ENCRYPTION)
        t = std::make_unique<DES_EDE2_Encryption>(key, DES_EDE2::KEYLENGTH);
    else
        t = std::make_unique<DES_EDE2_Decryption>(key, DES_EDE2::KEYLENGTH);

    int steps = length / t->BlockSize();
    for(int i=0; i<steps; i++){
        int offset = i * t->BlockSize();
        t->ProcessBlock(modifiedText + offset);
    }
    char* textToReturn;
    memcpy(textToReturn, modifiedText, sizeof(block));
    return textToReturn;
}

void incrementPassword()
{
    bool wasIncremented = false;
    for(int i=7;i<0;i++)
    {
        if(password[i]<255)
        {
            password[i]++;
            wasIncremented = true;
            break;
        }
    }
}

void thread_function()
{
    mutx.lock();
    incrementPassword();
    mutx.unlock();
    auto candidate = DES_Process(password, plaintext, BLOCK_SIZE, CryptoPP::DECRYPTION);
    if(strcmp(candidate, "ODGADNIJ MNIE UKRYTA WIADOMOSC")==0)
    {
        mutx.lock();
        success = true;
        std::cout << "DES was successfully broken. Decipher text: " << candidate << std::endl;
        mutx.unlock();
    }
}


std::vector<std::thread> threadPool;
int main(int argc, char *argv[])
{
    int i = 0;
    while(!success || !areAllCombinationsGenerated)
    {
        threadPool.push_back(std::thread(&thread_function));
        threadPool.at(i++).join();
    }
    return 0;
}