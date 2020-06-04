package org.ofdrw.sign.verify.container;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.*;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.digest.SM3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ofdrw.core.signatures.SigType;
import org.ofdrw.gm.ses.parse.SESChainData;
import org.ofdrw.gm.ses.v1.*;
import org.ofdrw.sign.verify.SignedDataValidateContainer;
import org.ofdrw.sign.verify.exceptions.InvalidSignedValueException;

/**
 * 《《GM/T 0031-2014 安全电子签章密码技术规范》 电子印章数据验证
 * <p>
 * 注意：仅用于测试，电子签章验证请使用符合国家规范的流程进行！
 *
 * @author 权观宇
 * @since 2020-04-22 22:56:23
 */
public class SESV1ValidateContainer implements SignedDataValidateContainer {
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
        //电子印章
        SESeal eseal = toSign.getEseal();
        byte[] expectDataHash = toSign.getDataHash().getOctets();


        // 比较原文摘要
        if (!Arrays.equals(actualDataHash, expectDataHash)) {
            throw new InvalidSignedValueException("Signature.xml 文件被篡改，电子签章失效。("
                    + toSign.getPropertyInfo().getString() + ")", 1);
        }

        // 签章信息是否在印章列表中
        ASN1OctetString cert = toSign.getCert();
        byte[] certDER =  cert.getOctets();

        ASN1Sequence certList = eseal.getEsealInfo().getProperty().getCertList();
        Enumeration<?> e = certList.getObjects();
        Boolean pass = false;
        while (e.hasMoreElements()){
            ASN1OctetString octetString = ASN1OctetString.getInstance(e.nextElement());
            if(cert.equals(octetString)){
                pass = true;
                break;
            }
        }

        if(!pass){
            throw new InvalidSignedValueException("签章证书不在制章列表当中", 2);
        }

        // 制章人对印章签名是否合法
        SES_SignInfo makeSampeSignInfo = eseal.getSignInfo();
        ASN1OctetString makeSampelCert = makeSampeSignInfo.getCert();
        byte[] makeSampelDER =  makeSampelCert.getOctets();

        FileOutputStream out=new FileOutputStream("x509data.txt");
        for(int i=0;i<makeSampelDER.length;i++) {
            out.write(makeSampelDER[i]);
        }
        out.close();
        System.out.println("输出成功");

        X509Certificate makeSampeCertificate = (X509Certificate) new CertificateFactory().engineGenerateCertificate(new ByteArrayInputStream(makeSampelDER));



        ASN1EncodableVector v = new ASN1EncodableVector(3);

        //ses_sealinfo信息
        v.add(eseal.getEsealInfo());
        //制章人证书
        v.add(makeSampelCert);
        //制章人算法
        v.add(makeSampeSignInfo.getSignatureAlgorithm());

        //初始化验证器，设置算法
        Signature makeSampeSg = Signature.getInstance( makeSampeSignInfo.getSignatureAlgorithm().getId(),
                new BouncyCastleProvider());
        //设置制章人证书
        makeSampeSg.initVerify(makeSampeCertificate);
        //设置待签值
        byte[] ders1 = new DERSequence(v).getEncoded();

        makeSampeSg.update(ders1);
        //获取签名值
        byte[] sigVal = makeSampeSignInfo.getSignData().getBytes();
        byte[] sigVal1 = rsPlainByteArrayToAsn1(sigVal);

        //验证
        if (!makeSampeSg.verify(sigVal1)) {
            throw new InvalidSignedValueException("制章人数据签名值不匹配，电子签章数据失效。", 1);
        }


        // 预期的电子签章数据，签章值
        byte[] expSigVal = sesSignature.getSignature().getOctets();

        Signature sg = Signature.getInstance( toSign.getSignatureAlgorithm().getId(),
                new BouncyCastleProvider());
        // 构造证书对象
        Certificate signCert = new CertificateFactory()
                .engineGenerateCertificate(new ByteArrayInputStream(certDER));
        sg.initVerify(signCert);
        byte[] ders = toSign.getEncoded("DER");

        sg.update(ders);
        byte[] bytes = rsPlainByteArrayToAsn1(expSigVal);

        if (!sg.verify(bytes)) {
            throw new InvalidSignedValueException("电子签章数据签名值不匹配，电子签章数据失效。", 1);
        }

        //检查签名时间戳
        ASN1BitString timeInfo = toSign.getTimeInfo();
        try {
            String s = new String(timeInfo.getOctets(), "UTF-8");
            ASN1UTCTime asn1UTCTime = new ASN1UTCTime(s);
            ((X509Certificate) signCert).checkValidity(asn1UTCTime.getDate());
        } catch (UnsupportedEncodingException | ParseException exception) {
            exception.printStackTrace();
        } catch (CertificateExpiredException | CertificateNotYetValidException exception) {
            throw new InvalidSignedValueException("签名时间不在证书有效期范围内", 2);
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

        SES_Signature sesSignature = SES_Signature.getInstance(signedValue);
        TBS_Sign toSign = sesSignature.getToSign();
        byte[] signCertDER =  toSign.getCert().getOctets();
        //设置时间戳
        ASN1BitString timeInfo = toSign.getTimeInfo();
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

        byte[] makingStampCertDER = toSign.getEseal().getSignInfo().getCert().getOctets();
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
        //sm2签名值是由两部分组成（r，s）详情请参考GB/T 32918.5-2017
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

    /**
     * byte数组转换为二进制字符串,每个字节以","隔开
     **/
    public static String byteArrToBinStr(byte[] b) {
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            result.append(Long.toString(b[i] & 0xff, 2) + ",");
        }
        return result.toString().substring(0, result.length() - 1);
    }

}
