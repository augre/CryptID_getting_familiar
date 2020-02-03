#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"

const int BASE = 10;

PublicParameters readPublicParFromFile()
{
    FILE * fp;

    PublicParameters publicParameters;

    mpz_t a, b, fieldOrder, q, px, py, ppx, ppy;
    mpz_inits(a, b, fieldOrder, q, px, py, ppx, ppy, NULL);

    fp = fopen ("PP/PP.ellipticCurve.a","r");
    if (fp != NULL)
    {
        mpz_inp_str(a, fp, BASE);
        fclose(fp);
    }

    fp = fopen ("PP/PP.ellipticCurve.b","r");
    if (fp != NULL)
    {
        mpz_inp_str(b, fp, BASE);
        fclose(fp);
    }

    fp = fopen ("PP/PP.ellipticCurve.fieldOrder","r");
    if (fp != NULL)
    {
        mpz_inp_str(fieldOrder, fp, BASE);
        fclose(fp);
    }
    publicParameters.ellipticCurve = ellipticCurve_init(a, b, fieldOrder);

    fp = fopen ("PP/PP.q","r");
    if (fp != NULL)
    {
        mpz_inp_str(q, fp, BASE);
        fclose(fp);
    }
    mpz_init(publicParameters.q);
    mpz_set(publicParameters.q, q);

    fp = fopen ("PP/PP.pointP.x","r");
    if (fp != NULL)
    {
        mpz_inp_str(px, fp, BASE);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointP.y","r");
    if (fp != NULL)
    {
        mpz_inp_str(py, fp, BASE);
        fclose(fp);
    }
    publicParameters.pointP = affine_init(px, py);

    fp = fopen ("PP/PP.pointPpublic.x","r");
    if (fp != NULL)
    {
        mpz_inp_str(ppx, fp, BASE);
        fclose(fp);
    }

    fp = fopen ("PP/PP.pointPpublic.y","r");
    if (fp != NULL)
    {
        mpz_inp_str(ppy, fp, BASE);
        fclose(fp);
    }
    publicParameters.pointPpublic = affine_init(ppx, ppy);

    fp = fopen ("PP/PP.hashf","r");
    if (fp != NULL)
    {
        int i = 0;
        fread(&i, sizeof(int), 1, fp);
        publicParameters.hashFunction = (HashFunction) i;
        fclose(fp);
    }

    return publicParameters;
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

CipherTextTuple readCipherTextFromFile()
{
    CipherTextTuple ciphertext;

    FILE * fp;

    fp = fopen("CT/cipher", "rb");
    if (fp != NULL) {

        //fread(&ciphertext.cipherU, sizeof(ciphertext.cipherU), 1, fp);
        fread(&ciphertext.cipherVLength, sizeof(ciphertext.cipherVLength), 1, fp);

	ciphertext.cipherV = malloc(ciphertext.cipherVLength + 1);
        fread(ciphertext.cipherV, ciphertext.cipherVLength + 1, 1, fp);
        fread(&ciphertext.cipherWLength, sizeof(ciphertext.cipherWLength), 1, fp);

	ciphertext.cipherW = malloc(ciphertext.cipherWLength + 1);
        fread(ciphertext.cipherW, ciphertext.cipherWLength + 1, 1, fp);

        fclose(fp);
    }

    else printf("Can't open file");
    printf("kiolvasott:\n");
    printf("VLength: %lu\n", ciphertext.cipherVLength);
    printf("%s\n", ciphertext.cipherV);
    printf("%lu\n", ciphertext.cipherWLength);
    printf("%s\n", ciphertext.cipherW);

    mpz_t x, y;
    mpz_inits(x, y, NULL);
    fp = fopen ("CT/cipherUx","r");
    if (fp != NULL) {
        mpz_inp_str(x, fp, 10);
        fclose(fp);
    }

    fp = fopen ("CT/cipherUy","r");
    if (fp != NULL) {
        mpz_inp_str(y, fp, 10);
        fclose(fp);
    }

    ciphertext.cipherU = affine_init(x, y);

    printf ("  read in  "); mpz_out_str (stdout, 10, ciphertext.cipherU.x); printf("\n");
    printf ("  read in  "); mpz_out_str (stdout, 10, ciphertext.cipherU.y); printf("\n");
    return ciphertext;
}

int main()
{
    PublicParameters publicParameters2 = readPublicParFromFile();
    (validation_isTypeOneEllipticCurve(publicParameters2.ellipticCurve)) ? (printf("TypeOneEllipticCurve valid\n")) : (printf("TypeOneEllipticCurve invalid\n"));
    (validation_isProbablePrime(publicParameters2.q)) ? (printf("ProbablePrime q valid\n")) : (printf("ProbablePrime q invalid\n"));
    (validation_isAffinePointValid(publicParameters2.pointP, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("pointP valid\n")) : (printf("pointP invalid\n"));
    (validation_isAffinePointValid(publicParameters2.pointPpublic, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("pointPpublic valid\n")) : (printf("pointPpublic invalid\n"));
    (validation_isPublicParametersValid(publicParameters2)) ? (printf("PublicParameters valid\n")) : (printf("PublicParameters  invalid\n"));

    AffinePoint pk2;
    pk2 = readPrivateKeyFromFiles();

    (validation_isAffinePointValid(pk2, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("privateKey valid\n")) : (printf("privateKey  invalid\n"));

    CipherTextTuple ct = readCipherTextFromFile();

    (validation_isAffinePointValid(ct.cipherU, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("cipherU aff point valid\n")) : (printf("cipherU aff point invalid\n"));
    (ct.cipherV) ? (printf("cipherV valid\n")) : (printf("cipherV invalid\n"));
    (ct.cipherVLength != 0) ? (printf("cipherVlength valid\n")) : (printf("cipherVlength invalid\n"));
    (ct.cipherW) ? (printf("cipherW valid\n")) : (printf("cipherW invalid\n"));
    (ct.cipherWLength != 0) ? (printf("cipherWlength valid\n")) : (printf("cipherWlength invalid\n"));


    (validation_isCipherTextTupleValid(ct, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("read cipher valid\n")) : (printf("read cipher invalid\n"));

    char *plaintext;
    if (CRYPTID_SUCCESS != cryptid_decrypt(&plaintext, pk2, ct, publicParameters2))
    {
        printf("Decrypt failed\n");
        return -1;
    }

    printf("Plaintext:\n%s\n", plaintext);

}
