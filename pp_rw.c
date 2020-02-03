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
    writePublicParToFile(publicParameters);
    PublicParameters publicParameters2 = readPublicParFromFile();
    (validation_isTypeOneEllipticCurve(publicParameters2.ellipticCurve)) ? (printf("TypeOneEllipticCurve valid\n")) : (printf("TypeOneEllipticCurve invalid\n"));
    (validation_isProbablePrime(publicParameters2.q)) ? (printf("ProbablePrime q valid\n")) : (printf("ProbablePrime q invalid\n"));
    (validation_isAffinePointValid(publicParameters2.pointP, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("pointP valid\n")) : (printf("pointP invalid\n"));
    (validation_isAffinePointValid(publicParameters2.pointPpublic, publicParameters2.ellipticCurve.fieldOrder)) ? (printf("pointPpublic valid\n")) : (printf("pointPpublic invalid\n"));
    (validation_isPublicParametersValid(publicParameters2)) ? (printf("PublicParameters valid\n")) : (printf("PublicParameters  invalid\n"));
}
