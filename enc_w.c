#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"

const int BASE = 10;

void writePublicParToFile(PublicParameters* publicParameters)
{
    FILE * fp;

    fp = fopen ("PP/PP.ellipticCurve.a","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->ellipticCurve.a);
        fclose(fp);
    }

    fp = fopen ("PP/PP.ellipticCurve.b","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->ellipticCurve.b);
        fclose(fp);
    }

    fp = fopen ("PP/PP.ellipticCurve.fieldOrder","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->ellipticCurve.fieldOrder);
        fclose(fp);
    }

    fp = fopen ("PP/PP.q","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->q);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointP.x","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->pointP.x);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointP.y","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->pointP.y);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointPpublic.x","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->pointPpublic.x);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointPpublic.y","w+");
    if (fp != NULL)
    {
        mpz_out_str(fp, BASE, publicParameters->pointPpublic.y);
        fclose(fp);
    }

    fp = fopen ("PP/PP.hashf","wb");
    if (fp != NULL) {

        fwrite(&publicParameters->hashFunction, sizeof(publicParameters->hashFunction), 1, fp);

        fclose(fp);
    }

}

void writeCipherTextToFile(CipherTextTuple* ciphertext)
{
    FILE * fp;
    fp = fopen ("CT/cipher","wb");
    if (fp != NULL) {

        //fwrite(&ciphertext->cipherU, sizeof(ciphertext->cipherU), 1, fp);

        fwrite(&ciphertext->cipherVLength, sizeof(ciphertext->cipherVLength), 1, fp);
        fwrite(ciphertext->cipherV, ciphertext->cipherVLength + 1, 1, fp);

        fwrite(&ciphertext->cipherWLength, sizeof(ciphertext->cipherWLength),1, fp);
        fwrite(ciphertext->cipherW, ciphertext->cipherWLength + 1, 1, fp);

        fclose(fp);
    }
    printf("beleirt:\n");
    printf("VLength: %lu\n", ciphertext->cipherVLength);
    printf("%s\n", ciphertext->cipherV);
    printf("%lu\n", ciphertext->cipherWLength);
    printf("%s\n", ciphertext->cipherW);

    fp = fopen ("CT/cipherUx","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, ciphertext->cipherU.x);
        fclose(fp);
    }
    printf ("  wrote  "); mpz_out_str (stdout, 10, ciphertext->cipherU.x); printf("\n");

    fp = fopen ("CT/cipherUy","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, ciphertext->cipherU.y);
        fclose(fp);
    }
    printf ("  wrote  "); mpz_out_str (stdout, 10, ciphertext->cipherU.y); printf("\n");
}

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

    writeCipherTextToFile(ciphertext);
    writePublicParToFile(publicParameters);
    writePrivateKeyToFiles(privateKey);
}
