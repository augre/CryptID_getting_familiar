#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"


void writePrivateKeyToFiles(AffinePoint privateKey)
{
    FILE * fp;
    fp = fopen ("PK/privateX","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, privateKey.x);
        fclose(fp);
    }

    fp = fopen ("PK/privateY","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, privateKey.y);
        fclose(fp);
    }
}

AffinePoint readPrivateKeyFromFiles()
{
    AffinePoint privateKey;
    mpz_t x, y;
    mpz_inits(x, y, NULL);

    FILE * fp;
    fp = fopen ("PK/privateX","r");
    if (fp != NULL)
    {
        mpz_inp_str(x, fp, 10);
        fclose(fp);
    }
    else printf("Can't open file");

    fp = fopen ("PK/privateY","r");
    if (fp != NULL)
    {
        mpz_inp_str(y, fp, 10);
        fclose(fp);
    }
    else printf("Can't open file");

    privateKey = affine_init(x, y);

    printf ("privateY  read in  "); mpz_out_str (stdout, 10, privateKey.y); printf("\n");
    printf ("privateX  read in  "); mpz_out_str (stdout, 10, privateKey.x); printf("\n");

    return privateKey;
}


int main()
{
    const char *message = "Ironic.";
    const char *identity = "darth.plagueis@sith.com";

    PublicParameters* publicParameters = malloc(sizeof (PublicParameters));
    mpz_t masterSecret;
    mpz_init(masterSecret);
    mpz_init(publicParameters->q);
    if (CRYPTID_SUCCESS != cryptid_setup(LOWEST, publicParameters, masterSecret))
    {
        printf("Setup failed\n");
        return -1;
    }

    CipherTextTuple* ciphertext = malloc(sizeof (CipherTextTuple));
    if (CRYPTID_SUCCESS != cryptid_encrypt(ciphertext, message, strlen(message), identity, strlen(identity), *publicParameters))
    {
        printf("Encrypt failed\n");
        return -1;
    }


    AffinePoint privateKey;
    if (CRYPTID_SUCCESS != cryptid_extract(&privateKey, identity, strlen(identity), *publicParameters, masterSecret))
    {
        printf("Extract failed\n");
        return -1;
    }

    writePrivateKeyToFiles(privateKey);

    AffinePoint pk2;
    pk2 = readPrivateKeyFromFiles();

    (validation_isAffinePointValid(pk2, publicParameters->ellipticCurve.fieldOrder)) ? (printf("privateKey valid\n")) : (printf("privateKey  invalid\n"));
}
