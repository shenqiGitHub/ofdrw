package org.ofdrw.sign.verify.exceptions;

/**
 * 电子签名数据失效异常
 *
 * @author 权观宇
 * @since 2020-04-22 02:17:28
 */
public class InvalidSignedValueException extends OFDVerifyException {
    /**
     * 失效原因
     */
    private String reason;

    /**
     * 状态码  1文件被篡改修改， 2 签章时间失效
     */
    private Integer code;

    public InvalidSignedValueException(String reason) {
        super("电子签章数据失效：" + reason);
        this.reason = reason;
    }

    public InvalidSignedValueException(String reason, Integer code) {
        super("电子签章数据失效：" + reason);
        this.reason = reason;
        this.code = code;
    }

    public InvalidSignedValueException(String reason, Throwable cause) {
        super("电子签章数据失效：" + reason, cause);
        this.reason = reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getReason() {
        return reason;
    }
}
