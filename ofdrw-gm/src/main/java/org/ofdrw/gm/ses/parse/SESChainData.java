package org.ofdrw.gm.ses.parse;

import java.security.cert.Certificate;

/**
 * 区块链入链所需的数据
 */
public class SESChainData {
  /**
   * 签章人证书对象
   */
  private Certificate signCert;

  /**
   * 制章人证书对象
   */
  private Certificate makingStampCert;

  /**
   * 图片二进制
   */
  private byte[] ImageOctets;

  /**
   * 图片类型
   */
  private String imageSuffix;

  /**
   * signxml文件的路径标识
   */
  private String signFileLocStr;

  private Long signTime;

  public Certificate getSignCert() {
    return signCert;
  }

  public void setSignCert(Certificate signCert) {
    this.signCert = signCert;
  }

  public Certificate getMakingStampCert() {
    return makingStampCert;
  }

  public void setMakingStampCert(Certificate makingStampCert) {
    this.makingStampCert = makingStampCert;
  }

  public byte[] getImageOctets() {
    return ImageOctets;
  }

  public void setImageOctets(byte[] imageOctets) {
    ImageOctets = imageOctets;
  }

  public String getImageSuffix() {
    return imageSuffix;
  }

  public void setImageSuffix(String imageSuffix) {
    this.imageSuffix = imageSuffix;
  }

  public String getSignFileLocStr() {
    return signFileLocStr;
  }

  public void setSignFileLocStr(String signFileLocStr) {
    this.signFileLocStr = signFileLocStr;
  }

  public Long getSignTime() {
    return signTime;
  }

  public void setSignTime(Long signTime) {
    this.signTime = signTime;
  }
}
