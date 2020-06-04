package org.ofdrw.gm.ses.v3;

import org.bouncycastle.asn1.*;
import org.ofdrw.gm.ses.v3.SES_SealInfo;

import java.io.IOException;
import java.util.Enumeration;

/**
 * 电子印章数据
 *
 * @author 权观宇
 * @since 2020-04-19 15:33:55
 */
public class SESeal extends ASN1Object {
    /**
     * 印章信息
     */
    private SES_SealInfo esealInfo;

    /**
     * 制章人的签名值
     * <p>
     * 制章人对电子印章格式中印章信息SES_SealInfo、制章人证书、签名算法标识符按 SEQUENCE方式组成的信息内容的数字签名
     */
    private DERBitString signData;

    public SESeal() {
        super();
    }

    public SESeal(SES_SealInfo esealInfo, DERBitString signData) {
        this.esealInfo = esealInfo;
        this.signData = signData;
    }

    public SESeal(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        esealInfo = SES_SealInfo.getInstance(e.nextElement());
        signData = (DERBitString) e.nextElement();
    }

    public static SESeal getInstance(Object o) {
        if (o instanceof SESeal) {
            return (SESeal) o;
        } else if (o != null) {
            byte[] octets = ((DEROctetString) o).getOctets();
            ASN1Sequence instance = ASN1Sequence.getInstance(octets);
            return new SESeal(instance);
        }
        return null;
    }

    public SES_SealInfo getEsealInfo() {
        return esealInfo;
    }

    public SESeal setEsealInfo(SES_SealInfo esealInfo) {
        this.esealInfo = esealInfo;
        return this;
    }

    public DERBitString getSignData() {
        return signData;
    }

    public SESeal setSignData(DERBitString signData) {
        this.signData = signData;
        return this;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(esealInfo);
        v.add(signData);
        try {
            return new DEROctetString(new DERSequence(v).getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
