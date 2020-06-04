package org.ofdrw.gm.ses.v1;

import java.security.Security;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.ofdrw.gm.cert.PKCS12Tools;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试电子签章数据产生
 * <p>
 * 注意：电子签章请使用符合国家规范具有国家型号证书的设备进行！
 *
 * @author 权观宇
 * @since 2020-04-21 01:27:57
 */
class SES_SignatureTest {

    static{
        try{
            Security.addProvider(new BouncyCastleProvider());
        }catch(Exception e)
        { e.printStackTrace(); } }

    @Test
    void build() throws Exception {


        Path p = Paths.get("src/test/resources", "UserV1.esl");
        final Path out = Paths.get("target/SignedValue.dat");

        Path userP12 = Paths.get("src/test/resources", "USER.p12");
        Certificate userCert = PKCS12Tools.ReadUserCert(userP12, "private", "777777");

        byte[] mockDigest = new byte[32];
        SESeal seal = SESeal.getInstance(Files.readAllBytes(p));
        String propertyInfo = "/Doc_0/Signs/Signatures.xml";
        ASN1UTCTime signUTCTime = new ASN1UTCTime(new Date(), Locale.CHINA);
        TBS_Sign tbsSign = new TBS_Sign()
                .setVersion(new ASN1Integer(1))
                .setEseal(seal)
                .setTimeInfo(new DERBitString(signUTCTime))
                .setDataHash(new DERBitString(mockDigest))
                .setPropertyInfo(new DERIA5String(propertyInfo))
                .setCert(new DEROctetString(userCert.getEncoded()))
                .setSignatureAlgorithm(GMObjectIdentifiers.sm2sign_with_sm3);


        char[] pwd = "777777".toCharArray();
        KeyStore userKs = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        try (InputStream rootKsIn = Files.newInputStream(userP12)) {
            userKs.load(rootKsIn, pwd);

            // 取得印章制作者证书的私钥
            PrivateKey privateKey = (PrivateKey) userKs.getKey("private", pwd);
            Signature signature = Signature.getInstance("SM3withSm2", "BC");
            signature.initSign(privateKey);
            signature.update(tbsSign.getEncoded("DER"));
            byte[] sign = signature.sign();
            SES_Signature sesSignature = new SES_Signature(tbsSign, new DERBitString(sign));
            Files.write(out, sesSignature.getEncoded("DER"));
        }

    }
}