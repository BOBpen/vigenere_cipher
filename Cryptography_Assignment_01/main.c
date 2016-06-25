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

#define KEY_LENGTH 4 // Can be anything from 1 to 13
#define MIN_KEY_LENGTH 1
#define MAX_KEY_LENGTH 13
#define KEY_SPACE 256
#define ENGLISH_LETTER_FREQUENCY 1.

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
    unsigned char key[KEY_LENGTH] = {0x6C, 0x75, 0x6B, 0x65}; // luke
    
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
    //FILE *cipherFile = fopen("ctext.txt", "r");
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
    size_t *frequency = malloc(sizeof(size_t) * KEY_SPACE);
    double summations[MAX_KEY_LENGTH];
    memset(summations, 0, sizeof(double) * MAX_KEY_LENGTH);
    
    // Make sure we are operating on valid key lengths
    assert(MIN_KEY_LENGTH > 0);
    assert(MIN_KEY_LENGTH < MAX_KEY_LENGTH);
    // So we have to try every possible key length
    for (size_t n = MIN_KEY_LENGTH; n <= MAX_KEY_LENGTH; ++n) {
        
        double averageSummation = 0.;
        
        for (size_t k = 0; k < n; ++k) {
            memset(stream, 0x00, size);
            memset(frequency, 0, sizeof(size_t) * KEY_SPACE);
            
            size_t j = 0; // This will be the length of the stream
            for (size_t i = k; i < size; i += n) { // Start from the ki position
                stream[j++] = cipherStream[i];
            }
            
            // For each position in stream, record the frequency of each byte
            for (size_t i = 0; i < j; ++i) {
                frequency[stream[i]] += 1;
            }
            
            size_t summation = 0.;
            for (size_t i = 0; i < KEY_SPACE; ++i) { // Could improve by slightly limiting this loop (65-127?)
                summation += frequency[i] * (frequency[i] - 1);
            }
            
            averageSummation += (double)summation / (j * (j - 1));
        }

        summations[n - 1] = averageSummation / n;
    }
    
    double max = 0.;
    size_t keyLength = 0;
    for (size_t i = 0; i < 256; ++i) {
        if (max < summations[i]) {
            max = summations[i];
            keyLength = i + 1; // Add 1 to adjust for 0 based indexing.
        }
    }

    
        /*
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
            
            b = b * b;
            
            
            // Frequencies of lowercase letters (as a fraction of all lowercase
            // letters) should be close to known English-letter frequencies
            return 0;
        }
        
        // Compute the frequencies of each byte in this selection
    }
    */
    fclose(cipherFile);
    free(stream);
    
    return 0;
}























