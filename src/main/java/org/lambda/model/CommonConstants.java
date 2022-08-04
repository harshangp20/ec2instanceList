package org.lambda.model;

import java.text.SimpleDateFormat;

public class CommonConstants {

    public static boolean S3_WEB_REPORT_NAME_DETAILS = true;
    public static final String DEFAULT_REGION = "ap-south-1";
    public static String DYNAMODB_TABLE = "MsOpsAudit";
    public static SimpleDateFormat formatter = new SimpleDateFormat("YYYY-MM-DD'T'HH:mm:ss.SSS'Z'");
    public static String S3_JSON_REPORT_BUCKET = "msops-audit-reports-parth";
    public static boolean S3_WEB_REPORT_OBFUSCATE_ACCOUNT = false;
    public static boolean SCRIPT_OUTPUT_JSON = true;
    public static boolean S3_JSON_REPORT = true;
    public static int S3_JSON_REPORT_EXPIRE = 168;
    public static boolean OUTPUT_ONLY_JSON = false;
    public static boolean SEND_REPORT_URL_TO_SNS = false;
    public static String SNS_TOPIC_ARN = "CHANGE_ME_TO_YOUR_TOPIC_ARN";
    public static int DAYS_DIFF = 90;
    public static int DAYS_DIFFERENCE = 180;
    public static int MAXIMUM_NUMBERS_OF_SECURITY_GROUPS = 50;

}
