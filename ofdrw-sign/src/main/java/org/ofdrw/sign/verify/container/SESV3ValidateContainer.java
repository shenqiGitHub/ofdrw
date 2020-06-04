package org.ofdrw.sign.verify.container;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Arrays;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.digest.SM3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ofdrw.core.signatures.SigType;

import org.ofdrw.gm.ses.parse.SESChainData;
import org.ofdrw.gm.ses.v3.SES_ESPictrueInfo;
import org.ofdrw.gm.ses.v3.SES_Signature;
import org.ofdrw.gm.ses.v3.TBS_Sign;
import org.ofdrw.sign.verify.SignedDataValidateContainer;
import org.ofdrw.sign.verify.exceptions.InvalidSignedValueException;

import java.security.cert.X509Certificate;

/**
 * 《《GM/T 0031-2014 安全电子签章密码技术规范》 电子印章数据验证
 * <p>
 * 注意：仅用于测试，电子签章验证请使用符合国家规范的流程进行！
 *
 * @author 权观宇
 * @since 2020-04-22 22:56:23
 */
public class SESV3ValidateContainer implements SignedDataValidateContainer {
    private final static int RS_LEN = 32;


    @Override
    public void validate(SigType type,
                         String signAlgName,
                         byte[] tbsContent,
                         byte[] signedValue)
            throws InvalidSignedValueException, IOException, GeneralSecurityException {
        if (type == SigType.Sign) {
            throw new IllegalArgumentException("签名类型(type)必须是 Seal，不支持电子印章验证");
        }

        // 计算原文摘要
        MessageDigest md = new SM3.Digest();
        byte[] actualDataHash = md.digest(tbsContent);

        SES_Signature sesSignature = SES_Signature.getInstance(signedValue);
        TBS_Sign toSign = sesSignature.getToSign();
        byte[] expectDataHash = toSign.getDataHash().getOctets();


        // 比较原文摘要
        if (!Arrays.equals(actualDataHash, expectDataHash)) {
            throw new InvalidSignedValueException("Signature.xml 文件被篡改，电子签章失效。("
                    + toSign.getPropertyInfo().getString() + ")", 1);
        }

        // 预期的电子签章数据，签章值
        byte[] expSigVal = sesSignature.getSignature().getBytes();

        Signature sg = Signature.getInstance( toSign.getSignatureAlgorithm().getId(),
                new BouncyCastleProvider());
        byte[] certDER =  toSign.getCert().getOctets();
        // 构造证书对象
        X509Certificate signCert = (X509Certificate) new CertificateFactory()
                .engineGenerateCertificate(new ByteArrayInputStream(certDER));
        sg.initVerify(signCert);
        sg.update(toSign.getEncoded("DER"));
        byte[] bytes = rsPlainByteArrayToAsn1(expSigVal);
        if (!sg.verify(bytes)) {
            throw new InvalidSignedValueException("电子签章数据签名值不匹配，电子签章数据失效。", 1);
        }
    }

    /**
     * 供其他服务获取证书信息
     * @param signedValue
     * @return
     */
    @Override
    public SESChainData getSignCert(byte[] signedValue) throws CertificateException {
        SESChainData sesChainData = new SESChainData();

        org.ofdrw.gm.ses.v3.SES_Signature sesSignature = org.ofdrw.gm.ses.v3.SES_Signature.getInstance(signedValue);
        org.ofdrw.gm.ses.v3.TBS_Sign toSign = sesSignature.getToSign();
        byte[] signCertDER =  toSign.getCert().getOctets();
        //设置时间戳
        ASN1OctetString timeInfo = toSign.getTimeInfo();
        try {
            String s = new String(timeInfo.getOctets(), "UTF-8");
            ASN1UTCTime asn1UTCTime = new ASN1UTCTime(s);
            long time = asn1UTCTime.getDate().getTime();
            sesChainData.setSignTime(time);
        } catch (UnsupportedEncodingException | ParseException e) {
            e.printStackTrace();
        }
        // 构造签章人证书对象
        Certificate signCert = new CertificateFactory()
                .engineGenerateCertificate(new ByteArrayInputStream(signCertDER));
        sesChainData.setSignCert(signCert);

        byte[] makingStampCertDER = toSign.getEseal().getEsealInfo().getCert().getOctets();
        //构造制章人证书对象
        Certificate makingStampCert = new CertificateFactory()
                .engineGenerateCertificate(new ByteArrayInputStream(makingStampCertDER));
        sesChainData.setMakingStampCert(makingStampCert);

        //签章图片信息抽取
        SES_ESPictrueInfo picture = toSign.getEseal().getEsealInfo().getPicture();
        byte[] octets = picture.getData().getOctets();
        String imageSuffix = picture.getType().getString();
        sesChainData.setImageOctets(octets);
        sesChainData.setImageSuffix(imageSuffix);
        return sesChainData;
    }


    /**
     * 针对部分厂商的签名值不采用asn封装进行预处理
     * @param sign
     * @return
     */
    private static byte[] rsPlainByteArrayToAsn1(byte[] sign){
        if(sign.length != RS_LEN * 2) {
            return sign;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            DERSequence sequence = new DERSequence(v);
            return sequence.getEncoded("DER");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
