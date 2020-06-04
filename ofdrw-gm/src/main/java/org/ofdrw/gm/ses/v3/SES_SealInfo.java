package org.ofdrw.gm.ses.v3;

import org.bouncycastle.asn1.*;
import org.ofdrw.gm.ses.v3.ExtensionDatas;
import org.ofdrw.gm.ses.v3.SES_ESPictrueInfo;
import org.ofdrw.gm.ses.v3.SES_ESPropertyInfo;
import org.ofdrw.gm.ses.v3.SES_Header;
import org.ofdrw.gm.ses.v3.SES_SignInfo;

import java.util.Enumeration;

/**
 * 印章信息
 *
 * @author 权观宇
 * @since 2020-04-19 15:26:39
 */
public class SES_SealInfo extends ASN1Object {

    /**
     * 头信息
     */
    private SES_Header header;

    /**
     * 电子印章标识符
     * <p>
     * 电子印章数据唯一标识编码
     */
    private DERIA5String esID;

    /**
     * 印章属性信息
     */
    private org.ofdrw.gm.ses.v3.SES_ESPropertyInfo property;

    /**
     * 电子印章图片数据
     */
    private SES_ESPictrueInfo picture;

    /**
     * 签名算法标识
     */
    private ASN1ObjectIdentifier signatureAlgID;

    /**
     * 自定义数据
     */
    private org.ofdrw.gm.ses.v3.ExtensionDatas extDatas;


    /**
     * 代表对电子印章数据进行签名的制章人证书
     */
    private ASN1OctetString cert;

    public SES_SealInfo() {
        super();
    }

    public SES_SealInfo(SES_Header header,
                        DERIA5String esID,
                        org.ofdrw.gm.ses.v3.SES_ESPropertyInfo property,
                        SES_ESPictrueInfo picture,
                        SES_SignInfo signInfo,
                        ASN1OctetString cert,
                        ASN1ObjectIdentifier signatureAlgID,
                        org.ofdrw.gm.ses.v3.ExtensionDatas extDatas) {
        this.header = header;
        this.esID = esID;
        this.property = property;
        this.picture = picture;
        this.cert = cert;
        this.signatureAlgID = signatureAlgID;
        this.extDatas = extDatas;
    }

    public SES_SealInfo(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        header = SES_Header.getInstance(e.nextElement());
        esID = DERIA5String.getInstance(e.nextElement());
        property = org.ofdrw.gm.ses.v3.SES_ESPropertyInfo.getInstance(e.nextElement());
        picture = SES_ESPictrueInfo.getInstance(e.nextElement());
        cert = ASN1OctetString.getInstance(e.nextElement());
        signatureAlgID = ASN1ObjectIdentifier.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            extDatas = org.ofdrw.gm.ses.v3.ExtensionDatas.getInstance(e.nextElement());
        }
    }

    public static SES_SealInfo getInstance(Object o) {
        if (o instanceof SES_SealInfo) {
            return (SES_SealInfo) o;
        } else if (o != null) {
            return new SES_SealInfo(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public SES_Header getHeader() {
        return header;
    }

    public SES_SealInfo setHeader(SES_Header header) {
        this.header = header;
        return this;
    }

    public DERIA5String getEsID() {
        return esID;
    }

    public SES_SealInfo setEsID(DERIA5String esID) {
        this.esID = esID;
        return this;
    }

    public SES_SealInfo setEsID(String esID) {
        this.esID = new DERIA5String(esID);
        return this;
    }

    public org.ofdrw.gm.ses.v3.SES_ESPropertyInfo getProperty() {
        return property;
    }

    public SES_SealInfo setProperty(SES_ESPropertyInfo property) {
        this.property = property;
        return this;
    }

    public SES_ESPictrueInfo getPicture() {
        return picture;
    }

    public SES_SealInfo setPicture(SES_ESPictrueInfo picture) {
        this.picture = picture;
        return this;
    }

    public ASN1OctetString getCert(){
        return cert;
    }

    public SES_SealInfo setCert(ASN1OctetString cert){
        this.cert = cert;
        return this;
    }

    public ASN1ObjectIdentifier getSignatureAlgID() {
        return signatureAlgID;
    }

    public SES_SealInfo setSignatureAlgID(ASN1ObjectIdentifier signatureAlgID) {
        this.signatureAlgID = signatureAlgID;
        return this;
    }

    public org.ofdrw.gm.ses.v3.ExtensionDatas getExtDatas() {
        return extDatas;
    }

    public SES_SealInfo setExtDatas(ExtensionDatas extDatas) {
        this.extDatas = extDatas;
        return this;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(7);
        v.add(header);
        v.add(esID);
        v.add(property);
        v.add(picture);
        v.add(cert);
        v.add(signatureAlgID);
        if (extDatas != null) {
            v.add(extDatas);
        }
        return new DERSequence(v);
    }
}
