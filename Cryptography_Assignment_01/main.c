//
//  main.c
//  Cryptography_Assignment_01
//
//  Created by Luke Queenan on 2016-06-18.
//  Copyright © 2016 Luke Queenan. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define KEY_LENGTH 2 // Can be anything from 1 to 13
#define MIN_KEY_LENGTH 1
#define MAX_KEY_LENGTH 13

int vigenereEncrypt();
int crackVigenere();

int main(int argc, const char * argv[]) {
    //vigenereEncrypt();
    crackVigenere();
}

int vigenereEncrypt() {
    unsigned char ch;
    FILE *fpIn, *fpOut;
    int i;
    unsigned char key[KEY_LENGTH] = {0x00, 0x00};
    /* of course, I did not use the all-0s key to encrypt */
    
    fpIn = fopen("ptext.txt", "r");
    if (fpIn == NULL) {
        return 1;
    }
    fpOut = fopen("ctext.txt", "w");
    i=0;
    while (fscanf(fpIn, "%c", &ch) != EOF) {
        /* avoid encrypting newline characters */
        /* In a "real-world" implementation of the Vigenere cipher,
         every ASCII character in the plaintext would be encrypted.
         However, I want to avoid encrypting newlines here because
         it makes recovering the plaintext slightly more difficult... */
        /* ...and my goal is not to create "production-quality" code =) */
        if (ch!='\n') {
            fprintf(fpOut, "%02X", ch ^ key[i % KEY_LENGTH]); // ^ is logical XOR
            i++;
        }
    }
    
    fclose(fpIn);
    fclose(fpOut);
    return 0;
}

/* Attacking the (variant) Vigenere cipher requires two steps:
 * - Determine the key length (bytes in the key)
 * - Determine each byte of the key
 */
int crackVigenere() {

    // Open the ciphertext to decrypt
    FILE *cipherFile = fopen("ciphertext.txt", "r");
    if (cipherFile == NULL) {
        return 1;
    }
    // Get the length of the file and set it back to the beginning
    fseek(cipherFile, 0L, SEEK_END);
    const size_t size = ftell(cipherFile);
    rewind(cipherFile);
    
    unsigned char *cipherStream = malloc(sizeof(char) * size);

    // Read the file into memory for faster operation
    if (fread(cipherStream, sizeof(char), size, cipherFile) != size) {
        free(cipherStream);
        fclose(cipherFile);
        return 1;
    }
    
    unsigned char *stream = malloc(sizeof(char) * size);
    unsigned char *result = malloc(sizeof(char) * size);
    
    // So we have to try every possible key length
    // Make sure we are operating on valid key lengths
    assert(MIN_KEY_LENGTH > 0);
    assert(MIN_KEY_LENGTH < MAX_KEY_LENGTH);
    for (size_t n = MIN_KEY_LENGTH; n <= MAX_KEY_LENGTH; ++n) {

        memset(stream, 0x00, size);
        memset(result, 0x00, size);
        
        // Pick out every n'th character of the ciphertext
        for (size_t i = n - 1, j = 0; i < size; i += n, ++j) {
            stream[j] = cipherStream[i];
        }
        
        // Try decrypting the stream using every possible byte value b
        int test = 0;
        for (unsigned char b = 0x20; b < 0x7F; ++b) { // Can improve if key is English (32 - 127 only)
            size_t keepGoing = 1;
            test++;
            for (size_t j = 0; j < size; ++j) {
                stream[j] = stream[j] ^ b;
                
                // When the guess 'b' is correct, all bytes in the plaintext
                // stream will between 32 and 127 (ASCII values of the English
                // alphabet)
                if ((stream[j] < 0x20) || (stream[j] > 0x7F)) {
                    keepGoing = 0;
                    break;
                }
            }
            if (!keepGoing) {
                continue;
            }
            
            
            
            
            // Frequencies of lowercase letters (as a fraction of all lowercase
            // letters) should be close to known English-letter frequencies
            return 0;
        }
        
        // Compute the frequencies of each byte in this selection
    }
    
    fclose(cipherFile);
    free(stream);
    
    return 0;
}























