#include "rangeproofs.h"

#include "./hash/hash.h"
#include "./crypto_math/crypto-ops.h"
#include "../utils/utils.h"

typedef struct commitPair {
    key x;  //pub or secret key
    key mask;
} commitPair;

void d2b(bits amountb, uint64_t val) {
    int i = 0;
    while (val != 0) {
        amountb[i] = val & 1;
        i++;
        val >>= 1;
    }
    while (i < 64) {
        amountb[i] = 0;
        i++;
    }
}

void set_identity(ec_scalar out) {
    memcpy(out,I,32);
}

/* Generate a Borromean ring signature
 *  x:          Array of scalar masks (a_i) such that C_i = a_i*G + 2^i H * (b[i])
 *  P1:         Array of c_i values
 *  P2:         Array of C_i*H values
 *  indicies:   Binary representation of the amount being proven (0's and 1's)
 * 
 *  From the Borromean Ring Sig Paper (2017)
 *  Set of public keys: P_i,j   0<= i <=n - 1, 0<= j <=m_i - 1
 *      n: Number of rings
 *      m_i: Size of ring i        (In the case of range proofs, 2)
 *      j*_i: Signer's secret index (Pub keys P_i,j*_i)
 * 
 * 
 * 
 * PUT ALGORITHM HERE
 */
void generateBorromean(key64 x, key64 P1, key64 P2, bits indicies, borromean_sig* sig) {
    key64 R[2];     //The rings we are signing will have 2 members
    key64 alpha;    //Random scalar (k_i)

    int val = 0;    //Binary value we are proving (0 or 1)
    int prime = 0;  //Complimentary of val (opposite)

    ec_scalar c;
    ec_point temp;

    //Go through each 2^i
    for (size_t i = 0; i < 64; i++) {
        val = indicies[i];
        prime = (val + 1) % 2;
        random_scalar(alpha[i]);
        scalarMultBase(R[val][i], alpha[i]);    //R_val,j = k_i*G
        if (val == 0) {
            random_scalar(sig->s1[i]);
            hash_to_scalar(R[val][i],32,c);     //e = H(R_i,j)
            addKeys_double_multBase(R[prime][i],sig->s1[i],c,P2[i]); //R_prime,j = s_i*G + e*P_i
        }
    }

    //Need to create a version that takes in a key64
    hash_to_scalar(R[1][0],64*32,sig->e0);                  //e0 = H(R_0||...||R_n)

    for (size_t i = 0; i < 64; i++) {
        if (indicies[i] == 0) {
            sc_mulsub(sig->s0[i], x[i], sig->e0, alpha[i]); //s_0,i = k_i - x_i*e_0
        } else {
            random_scalar(sig->s0[i]);
            addKeys_double_multBase(temp, sig->s0[i], sig->e0, P1[i]);
            hash_to_scalar(temp,32,c);                      //c = H(s_0,i*G + e_0*P1_i)
            sc_mulsub(sig->s1[i], x[i],c,alpha[i]);         //s_1,i = k_i, x_i*c
        }
    }
}

/* Verify a Borromean ring signature
 *  P1:         Array of c_i values
 *  P2:         Array of C_i*H values
 *  sig:        Borromean signature that contains e0, s0's and s1's
 * 
 * 
 * PUT ALGORITHM HERE
 */
bool verifyBorromean(key64 P1, key64 P2, borromean_sig* sig) {
    ec_scalar c, e;
    ec_point t;
    key64 R;

    for (size_t i = 0; i < 64; i++) {
        addKeys_double_multBase(t, sig->s0[i], sig->e0, P1[i]); //t = s_0,i*G + e0*P1_i
        hash_to_scalar(t, 32, c);                               //c = e_i,j = H(t)
        addKeys_double_multBase(R[i],sig->s1[i],c,P2[i]);       //R_i = s_1,i*G + c*P2_i
    }
    hash_to_scalar(R,64*32,e);                                  //e = H(R_0||...||R_n)
    return isByteArraysEqual(e,sig->e0,32);                     //e ?= e0
}

/* Generate a range proof, that amount is within [0, 2^64)
 *  C:      All c_i values sum to this
 *  mask:   Hides the value that C is referencing
 *  amount: Value that we are proving
 *  proof:  Pre-allocated range proof
 * 
 * 
 * Should C be passed as pointer, or put into range_proof?
 */
void proveRange(key C, key mask, uint64_t amount, range_proof* proof) {
    //uint64_t amt = 1000;
    
    sc_0(mask);
    set_identity(C);

    bits b;
    d2b(b,amount);
    key64 ai, CiH, Ci;

    size_t i = 0;

    ge_p3 temp_p3;
    for (i = 0; i < 64; i++) {
        random_scalar(ai[i]);
        if (b[i] == 0) {                            //Commit to 0,  c_i=a_i*G
            scalarMultBase(Ci[i], ai[i]);
        } else if (b[i] == 1) {                     //Commit to 1, c_i=a_i*G + 2^i * H
            addKeys_multBase(Ci[i],ai[i],H2[i]);
        }

        sc_sub(CiH[i],Ci[i],H2[i]);                 //CiH = C_i - 2^i * H
        sc_add(mask,mask,ai[i]);                    //Add this sub-mask to mask
        sc_add(C, C, Ci[i]);                        //Add c_i to total C
    }

    generateBorromean(ai, Ci, CiH, b, &proof->sig);

    for (i = 0; i < 64; i++) {
        memcpy(proof->Ci[i], Ci[i], 32);
    }
}

//Inputs: C, rangeProof
bool verifyRange(key C, range_proof* proof) {
    key64 CiH;
    key calcC;  //Calculated C
    set_identity(calcC);

    for (size_t i = 0; i < 64; i++) {
        sc_sub(CiH[i], proof->Ci[i], H2[i]);        //CiH = C_i - 2^i * H
        sc_add(calcC, calcC, proof->Ci[i]);         //C += c_i
    }

    if (isByteArraysEqual(calcC, C, 32)) {
        return false;
    }

    //If the C's add up, check the proof
    return verifyBorromean(proof->Ci, CiH, &proof->sig);
}