package org.ofdrw.gm.ses.v3;

import org.bouncycastle.asn1.*;
import org.ofdrw.gm.ses.v3.TBS_Sign;

import java.util.Enumeration;

/**
 * 电子签章数据
 *
 * @author 权观宇
 * @since 2020-04-19 15:49:19
 */
public class SES_Signature extends ASN1Object {

    /**
     * 待电子签章数据
     */
    private TBS_Sign toSign;

    /**
     * 电子签章中签名值
     */
    private DERBitString signature;

    public SES_Signature() {
        super();
    }

    public SES_Signature(TBS_Sign toSign, DERBitString signature) {
        this.toSign = toSign;
        this.signature = signature;
    }


    public SES_Signature(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        toSign = TBS_Sign.getInstance(e.nextElement());
        signature = DERBitString.getInstance(e.nextElement());
    }


    public static SES_Signature getInstance(Object o) {
        if (o instanceof SES_Signature) {
            return (SES_Signature) o;
        } else if (o != null) {
            return new SES_Signature(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public TBS_Sign getToSign() {
        return toSign;
    }

    public SES_Signature setToSign(TBS_Sign toSign) {
        this.toSign = toSign;
        return this;
    }

    public ASN1BitString getSignature() {
        return signature;
    }

    public SES_Signature setSignature(DERBitString signature) {
        this.signature = signature;
        return this;
    }

    public SES_Signature setSignature(byte[] signature) {
        this.signature = new DERBitString(signature);
        return this;
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(toSign);
        v.add(signature);
        return new DERSequence(v);
    }
}
