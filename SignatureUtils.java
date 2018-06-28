package com.demo.common.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;

/**
 * @version V1.0
 * @Title: SignatureUtils
 * @Description: 签名工具类
 * @author: yu.sun
 * @date: 2018/6/28 17:46
 */
public class SignatureUtils {

    private Logger logger = LoggerFactory.getLogger(SignatureUtils.class);

    private final String DEFAULT_SIGNTYPE = "MD5";


    /**
     * 签名
     * @param params 请求参数集，所有参数必须已转换为字符串类型
     * @return 签名
     * @throws IOException
     */
    public String getSignature(HashMap<String,String> params,String signType,String secretKey) throws IOException{
        //请求参数排序，转换为字符串类型
        StringBuilder  baseStr =  sortParamsStr(params,secretKey);

        // 使用输入算法对待签名串求签
        byte[] bytes = null;
        try {

            switch (signType){
                case "MD5": bytes = SignatureUtils.getMD5Digest(baseStr.toString());// MessageDigest.getInstance(MD5TYPE);
                    break;
                case "SHA-1": bytes = SignatureUtils.getSHA1Digest(baseStr.toString());
                    break;
                default:
                    bytes = MessageDigest.getInstance(DEFAULT_SIGNTYPE).digest(baseStr.toString().getBytes("UTF-8"));
            }
        } catch (GeneralSecurityException ex) {
            throw new IOException(ex);
        }

        // 将MD5输出的二进制结果转换为小写的十六进制
        StringBuilder sign = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() == 1) {
                sign.append("0");
            }
            sign.append(hex);
        }
        return sign.toString();
    }

    /**
     * SHA1散列加密
     * @param data
     * @return
     * @throws IOException
     */
    private static byte[] getSHA1Digest(String data) throws IOException {
        byte[] bytes = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            bytes = md.digest(data.getBytes("UTF-8"));
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
        return bytes;
    }

    /**
     * MD5加密
     * @param data
     * @return
     * @throws IOException
     */
    private static byte[] getMD5Digest(String data) throws IOException {
        byte[] bytes = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            bytes = md.digest(data.getBytes("UTF-8"));
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
        return bytes;
    }

    /**
     * 转二进制
     * @param bytes
     * @return
     */
    private static String byte2hex(byte[] bytes) {
        StringBuilder sign = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() == 1) {
                sign.append("0");
            }
            sign.append(hex.toUpperCase());
        }
        return sign.toString();
    }


    /**
     * 参数排序方法，追加secret
     * @param params
     * @return
     */
    private StringBuilder sortParamsStr(HashMap<String,String> params,String secretKey){
        // 先将参数以其参数名的字典序升序进行排序
        Map<String, String> sortedParams = new TreeMap<>(params);
        Set<Map.Entry<String, String>> entrys = sortedParams.entrySet();

        // 遍历排序后的字典，将所有参数按"key=value"格式拼接在一起
        StringBuilder baseStr = new StringBuilder();
        for (Map.Entry<String, String> param : entrys) {
            baseStr.append(param.getKey()).append("=").append(param.getValue()).append("&");
        }
        logger.info("排序串结果为：{}",baseStr.deleteCharAt(baseStr.length()-1));
        return baseStr.deleteCharAt(baseStr.length()-1);
    }

    /**
     * 测试main方法
     * @param args
     */
    public static void main(String[] args) {
        SignatureUtils signatureUtils = new SignatureUtils();
        HashMap<String,String> reqParams = new HashMap<>();
        reqParams.put("userName","mcd_master");
        reqParams.put("passwrod","123456");
        String signRes = "";
        try {
            signRes = signatureUtils.getSignature(reqParams,"MD5","1231312");
        }catch (IOException e){
            signatureUtils.logger.info("签名失败");
        }
        signatureUtils.logger.info("签名成功，签名结果为：{}",signRes);


    }

}

