package org.lambda.service;

import com.amazonaws.HttpMethod;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.PrimaryKey;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.PublishRequest;
import com.google.gson.Gson;
import org.lambda.model.Clients;
import org.lambda.model.Request;
import org.lambda.model.Response;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.StsException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.*;

import static org.lambda.model.CommonConstants.*;

public class EC2CheckList implements RequestHandler<Request, List<Response>> {

    public Clients createClients(AssumeRoleResponse assumeRoleResponse) {

        String accessKey = assumeRoleResponse.credentials().accessKeyId();
        String secretKey = assumeRoleResponse.credentials().secretAccessKey();
        String sessionToken = assumeRoleResponse.credentials().sessionToken();

        BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(accessKey, secretKey, sessionToken);

        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard()
                .withRegion("ap-south-1")
                .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                .build();

        AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard()
                .withRegion(DEFAULT_REGION).build();

        DynamoDB dynamoDB = new DynamoDB(client);
        AmazonS3 s3 = AmazonS3ClientBuilder.standard()
                .withRegion(DEFAULT_REGION)
                .build();

        return new Clients(ec2Client, dynamoDB, s3);
    }

    void updateScanStatus(DynamoDB dynamoDB, String scanId, String accountId, String scanStatus) {

        try {
            Table table = dynamoDB.getTable(DYNAMODB_TABLE);
            Map<String, String> attrNames = new HashMap<>();
            attrNames.put("#A", "AWS_ACCOUNT_ID");
            attrNames.put("#S", "SCAN_STATUS");
            Map<String, Object> attrValues = new HashMap<>();
            attrValues.put(":val1", accountId);
            attrValues.put(":val2", scanStatus);

            table.updateItem(
                    new PrimaryKey("scanId", scanId),
                    "set #A = :val1, #S = :val2",
                    attrNames,
                    attrValues
            );
        } catch (Exception exception) {
            System.out.println("Unable to update scan status in DB:992 ");
        }
    }

    void updateReportStatus(DynamoDB dynamoDB, String scanId, String report_bucket, String report_key) {

        try {
            Table table = dynamoDB.getTable(DYNAMODB_TABLE);
            Map<String, String> attrNames = new HashMap<>();
            attrNames.put("#R", "REPORT_BUCKET");
            attrNames.put("#K", "REPORT_KEY");
            Map<String, Object> attrValues = new HashMap<>();
            attrValues.put(":val1", report_bucket);
            attrValues.put(":val2", report_key);

            table.updateItem(
                    new PrimaryKey("scanId", scanId),
                    "set #R = :val1, #K = :val2",
                    attrNames,
                    attrValues
            );
        } catch (Exception exception) {
            System.out.println("Unable to update scan status in DB:992 ");
        }
    }


    @Override
    public List<Response> handleRequest(Request request, Context context) {
        String accountNumber = null;
        SdkHttpClient httpClient = ApacheHttpClient
                .builder()
                .build();
        StsClient stsClient = StsClient.builder()
                .httpClient(httpClient)
                .build();
        String roleSessionName = "MsOpsAssumeRoleSession";
        String accountId = request.getAccountId();
        String roleArn = "**** IAM ROLE" + accountId + "********** ROLE"; //msopsstsrole
        AssumeRoleResponse assume_role_object = assumeGivenRole(stsClient, roleArn, roleSessionName);
        Clients clients = createClients(assume_role_object);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            accountNumber = get_account_number(assume_role_object);
        } catch (Exception exception) {
            updateReportStatus(clients.getDynamoDB(), request.scanId, accountId, exception.getMessage());
        }
        updateScanStatus(clients.getDynamoDB(), request.scanId, accountId, "SCANNING");
        System.out.println("Assumed account Id: " + accountNumber);
        List<Response> controls = new ArrayList<>();
        try {
            controls.add(control_1_1_snapshots(clients.getEc2Client()));
            controls.add(control_1_2_long_running_instances(clients.getEc2Client()));
            controls.add(control_1_3_ami_visibility(clients.getEc2Client()));
            controls.add(control_1_4_ami_encryption(clients.getEc2Client()));
//            controls.add(control_1_5_EC2_instance_limit_based_on_vCPU(clients.getEc2Client()));
//            controls.add(control_1_6_blocklisted_AMIs(clients.getEc2Client()));
            controls.add(control_1_7_determine_vpc_in_use(clients.getEc2Client()));
            controls.add(control_1_8_security_groups(clients.getEc2Client()));
            controls.add(control_1_9_EC2_AMI_too_old(clients.getEc2Client()));
            controls.add(control_1_11_detailed_monitoring_for_EC2(clients.getEc2Client()));
            controls.add(control_1_13_Scheduled_events_for_EC2(clients.getEc2Client()));
            controls.add(control_1_14_security_groups(clients.getEc2Client()));
            controls.add(control_1_15_termination_protection_for_ec2_instances(clients.getEc2Client()));
            controls.add(control_1_16_netbios_access(clients.getEc2Client()));
            controls.add(control_1_17_outbound_access(clients.getEc2Client()));
            controls.add(control_1_19_ec2_instance_using_iam_roles(clients.getEc2Client()));
            controls.add(control_1_20_cifs_access(clients.getEc2Client()));
            controls.add(control_1_21_icmp_access(clients.getEc2Client()));
            controls.add(control_1_24_mongo_db_access(clients.getEc2Client()));
            controls.add(control_1_25_MSSQL_access(clients.getEc2Client()));
            controls.add(control_1_26_My_SQL_access(clients.getEc2Client()));
            controls.add(control_1_27_oracle_access(clients.getEc2Client()));
            controls.add(control_1_29_Postgre_SQL_access(clients.getEc2Client()));
            controls.add(control_1_30_rdp_access(clients.getEc2Client()));
        } catch (Exception exception) {
            System.out.println("Error while processing EC2 Audit: " + exception.getMessage());
        }
        updateScanStatus(clients.getDynamoDB(), request.scanId, accountId, "COMPLETE");
        List<Response> json_report = new ArrayList<>();
        // Build JSON structure for console output if enabled
        if (SCRIPT_OUTPUT_JSON) {
            json_report = controls;
        }

        // Create JSON report file if enabled
        if (S3_JSON_REPORT) {
            String signedURL = s3Report(clients.getDynamoDB(), clients.getS3(), json_report, accountNumber, request);
            if (!OUTPUT_ONLY_JSON)
                System.out.println("SignedURL:\n" + signedURL);
            if (SEND_REPORT_URL_TO_SNS)
                sendResultsSNS(signedURL);
        }
        stsClient.close();
        return controls;
    }

    public String get_account_number(AssumeRoleResponse assume_role_object) {
        Region region = Region.AP_SOUTH_1;
        String accessKey = assume_role_object.credentials().accessKeyId();
        String secretKey = assume_role_object.credentials().secretAccessKey();
        String sessionToken = assume_role_object.credentials().sessionToken();
        String account;
        BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(accessKey, secretKey, sessionToken);

        if (!S3_WEB_REPORT_OBFUSCATE_ACCOUNT) {
            AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(sessionCredentials))
                    .withRegion(region.toString())
                    .build();

            account = stsClient.getCallerIdentity(new GetCallerIdentityRequest()).getAccount();
        }
        else {
            account = "111111111111";
        }
        return account;
    }

    public AssumeRoleResponse assumeGivenRole(StsClient stsClient, String roleArn, String roleSessionName) throws StsException {
        AssumeRoleRequest roleRequest = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName(roleSessionName)
                .build();

        AssumeRoleResponse roleResponse = stsClient.assumeRole(roleRequest);
        Credentials myCreds = roleResponse.credentials();
        // Display the time when the temp creds expire
        Instant exTime = myCreds.expiration();
        // Convert the Instant to readable date
        DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT)
                .withLocale(Locale.US)
                .withZone(ZoneId.systemDefault());

        formatter.format(exTime);
        return roleResponse;
    }

    public boolean time_gt_90_days(Date date) throws ParseException {
        // Get current time
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss+00:00");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        SimpleDateFormat idf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss+00:00");
        Date now = idf.parse(sdf.format(new Date()));
        long delta = Math.abs(now.getTime() - date.getTime());
        int daysDiff = (int) (delta / (1000 * 60 * 60 * 24) + 1);
        return daysDiff > DAYS_DIFF;
    }

    public boolean time_gt_180_days(Date date) throws ParseException {
        // Get current time
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss+00:00");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        SimpleDateFormat idf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss+00:00");
        Date now = idf.parse(sdf.format(new Date()));
        long delta = Math.abs(now.getTime() - date.getTime());
        int daysDiff = (int) (delta / (1000 * 60 * 60 * 24) + 1);
        return daysDiff > DAYS_DIFFERENCE;
    }

    String s3Report(DynamoDB dynamoDB, AmazonS3 s3, List<org.lambda.model.Response> control, String accountNumber, Request event) {
        String scanId = event.scanId;
        String json = new Gson().toJson(control);
        String reportName;
        if (S3_WEB_REPORT_NAME_DETAILS)
            reportName = scanId + "****REPORT NAME***" + ".json";
        else
            reportName = "EC2_REPORT.json";
        String S3_key = "******S3 KEY*****" + accountNumber + "/" + DEFAULT_REGION + '/' + reportName;
        try {
            Path tempPath = Files.createTempFile(null, null);
            Files.write(tempPath, json.getBytes(StandardCharsets.UTF_8));
            ObjectMetadata metadata = new ObjectMetadata();
            File tempFile = tempPath.toFile();
            metadata.setContentType("application/json");
            s3.putObject(S3_JSON_REPORT_BUCKET, S3_key, tempFile);
            tempFile.deleteOnExit();

        } catch (IOException e) {
            return "Failed to upload report to S3 because: " + e.getMessage();
        }
        updateReportStatus(dynamoDB, scanId, S3_JSON_REPORT_BUCKET, S3_key);
        Date expiration = new Date();
        long expTimeMillis = Instant.now().toEpochMilli();
        expTimeMillis += S3_JSON_REPORT_EXPIRE * 60L;
        expiration.setTime(expTimeMillis);

        GeneratePresignedUrlRequest generatePresignedUrlRequest =
                new GeneratePresignedUrlRequest(S3_JSON_REPORT_BUCKET, S3_key)
                        .withMethod(HttpMethod.GET)
                        .withExpiration(expiration);
        String url = s3.generatePresignedUrl(generatePresignedUrlRequest).toString();
        System.out.println(url);
        return url;
    }

    void sendResultsSNS(String url) {
        String region = (SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0];
        AmazonSNSClientBuilder snsClientBuilder = AmazonSNSClientBuilder.standard();
        snsClientBuilder.setRegion(region);
        AmazonSNS snsClient = snsClientBuilder.build();
        String pattern = "E MMM dd HH:mm:ss yyyy";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        String timeNow = simpleDateFormat.format(new Date());
        PublishRequest publishRequest = new PublishRequest()
                .withTopicArn(SNS_TOPIC_ARN)
                .withMessage("{default: " + url + "}")
                .withSubject("AWS CIS Benchmark report - " + timeNow)
                .withMessageStructure("json");
        snsClient.publish(publishRequest);
    }

    public Response control_1_1_snapshots(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.1";
        String description = "Ensure EC2 Instance Snapshots Should Not Be Public";
        Boolean scored = true;
        DescribeSnapshotsResult snapshotsResult = ec2Client.describeSnapshots(new DescribeSnapshotsRequest().withOwnerIds("self"));
        List<Snapshot> snapshots = snapshotsResult.getSnapshots();
        for (Snapshot snapshot : snapshots) {
            DescribeSnapshotAttributeRequest request = new DescribeSnapshotAttributeRequest();
            request.setSnapshotId(snapshot.getSnapshotId());
            request.setAttribute("createVolumePermission");
            DescribeSnapshotAttributeResult snapshotAttribute = ec2Client.describeSnapshotAttribute(request);
            List<CreateVolumePermission> createVolumePermissions = snapshotAttribute.getCreateVolumePermissions();
            for (CreateVolumePermission permission : createVolumePermissions) {
                // TODO check that we need to mentioned shared users or not ...
                if (permission.getGroup().equals("all") || permission.getUserId() != null) {
                    result = "false";
                    failReason = "EC2 snapshot is publicly accessible.";
                    offenders.add(snapshot.getSnapshotId());
                }
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_2_long_running_instances(AmazonEC2 ec2Client) throws ParseException {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.2";
        String description = "Ensure EC2 Instance Snapshots Should Not Be Relaunched";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setNextToken(null);
        List<Instance> instances = new ArrayList<>();
        do{
            DescribeInstancesResult instancesResult = ec2Client.describeInstances(request);
            List<Reservation> reservations = instancesResult.getReservations();
            for(Reservation reservation : reservations) {
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()){
                request.setNextToken(instancesResult.getNextToken());
            } else {
                break;
            }
        }
        while (request.getNextToken() != null);
        for(Instance instance : instances) {
            if (instance.getState().getName().equals("running") && time_gt_90_days(instance.getLaunchTime())){
                result = "false";
                failReason = "AWS instances is running > 90 days.";
                offenders.add(instance.getInstanceId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_3_ami_visibility(AmazonEC2 ec2Client)  {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.3";
        String description = "AMIs should not be public";
        Boolean scored = true;
        DescribeImagesRequest request = new DescribeImagesRequest().withOwners("self");
        DescribeImagesResult imagesResult = ec2Client.describeImages(request);
        List<Image> images = imagesResult.getImages();
        for (Image image : images) {
            if (image.getPublic()){
                result = "false";
                failReason = "AWS AMI found publicly.";
                offenders.add(image.getImageId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_4_ami_encryption(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.4";
        String description = "AWS AMIs should be encrypted";
        Boolean scored = true;
        DescribeImagesRequest request = new DescribeImagesRequest().withOwners("self");
        DescribeImagesResult imagesResult = ec2Client.describeImages(request);
        List<Image> images = imagesResult.getImages();
        for (Image image : images) {
            List<BlockDeviceMapping > mappings = image.getBlockDeviceMappings();
            for(BlockDeviceMapping mapping : mappings) {
                if (!mapping.getEbs().getEncrypted()){
                    result = "false";
                    failReason = "AMIs is not encrypted";
                    offenders.add(image.getImageId());
                }
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    /*public Response control_1_5_EC2_instance_limit_based_on_vCPU(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.5";
        String description = "EC2 instance limit should be based on vCPU";
        Boolean scored = true;
        GetServiceQuotaRequest request = new GetServiceQuotaRequest().withServiceCode("ec2").withQuotaCode("L-1216C47A");
        GetServiceQuotaResult result1 = new GetServiceQuotaResult();
        List<ServiceQuota> serviceQuotas = Collections.singletonList(result1.getQuota());
        for (ServiceQuota serviceQuota : serviceQuotas){

        }

        return new Response(result, failReason, offenders, scored, description, control);
    }*/

    /*public Response control_1_6_blocklisted_AMIs(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.6";
        String description = "Block listed AMIs must not be used";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setNextToken(null);
        List<Instance> instances = new ArrayList<>();
        do {
            DescribeInstancesResult instancesResult = ec2Client.describeInstances(request);
            List<Reservation> reservations = instancesResult.getReservations();
            for (Reservation reservation : reservations){
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()) {
                request.setNextToken(instancesResult.getNextToken());
            } else {
                break;
            }
        }
        while (request.getNextToken() != null);


        return new Response(result, failReason, offenders, scored, description, control);
    }
*/

    public Response control_1_7_determine_vpc_in_use(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.7";
        String description = "Ensure Default VPC should not be in use";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setNextToken(null);
        List<Vpc> defaultVPC = new ArrayList<>();
        DescribeVpcsResult vpcsResult = ec2Client.describeVpcs();
        for (Vpc vpc : vpcsResult.getVpcs()){
            if (vpc.getIsDefault()){
                defaultVPC.add(vpc);
            }
        }
        List<Instance>  instances = new ArrayList<>();
        do {
            DescribeInstancesResult instancesResult = ec2Client.describeInstances();
            List<Reservation> reservations = instancesResult.getReservations();
            for (Reservation reservation : reservations) {
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()) {
                request.setNextToken(instancesResult.getNextToken());
            }
            else {
                break;
            }
        }
        while (request.getNextToken() != null);
        for (Instance instance : instances) {
            for (Vpc vpc : defaultVPC) {
                if (vpc.getVpcId().equals(instance.getVpcId())) {
                    result = "false";
                    failReason = "AWS EC2 instance ids using default vpc id.";
                    offenders.add(instance.getInstanceId());
                }
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_8_security_groups(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.8";
        String description = "Ensure Security Groups have description.";
        Boolean scored = true;
        DescribeSecurityGroupsRequest request = new DescribeSecurityGroupsRequest();
        request.setNextToken(null);
        List<SecurityGroup> securityGroups = new ArrayList<>();
        do {
            DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(request);
            securityGroups.addAll(securityGroupsResult.getSecurityGroups());
            if (securityGroupsResult.getSecurityGroups().isEmpty()) {
                request.setNextToken(securityGroupsResult.getNextToken());
            } else {
                break;
            }
        }
        while (request.getNextToken() != null);
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getDescription() == null || securityGroup.getDescription().isEmpty()) {
                result = "false";
                failReason = "AWS Security Groups doesn't contains description.";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_9_EC2_AMI_too_old(AmazonEC2 ec2Client) throws ParseException {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.9";
        String description = "Ensure AMIs should not be grater than 180 days";
        Boolean scored = true;
        DescribeImagesRequest request = new DescribeImagesRequest();
        request.setOwners(Collections.singleton("self"));
        DescribeImagesResult imagesResult = ec2Client.describeImages(request);
        List<Image> images = imagesResult.getImages();
        for (Image image : images) {
           if (time_gt_180_days(formatter.parse(image.getCreationDate()))) {
               result = "false";
               failReason = "AMI age is greater than 180 days";
               offenders.add(image.getImageId());
           }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_11_detailed_monitoring_for_EC2(AmazonEC2 ec2Client){
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.11";
        String description = "Ensure Detailed monitoring should be enabled on EC2 instances.";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("instance-state-name" , Collections.singletonList("running")));
        request.setFilters(filters);
        List<Instance> instances = new ArrayList<>();
        do {
            DescribeInstancesResult instancesResult = ec2Client.describeInstances(request);
            List<Reservation> reservations = instancesResult.getReservations();
            for (Reservation reservation : reservations ) {
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()) {
                request.setNextToken(instancesResult.getNextToken());
            }
            else {
                break;
            }
        }
        while(request.getNextToken() != null);
        for (Instance instance : instances ) {
            if (instance.getMonitoring().getState().equalsIgnoreCase("disabled") ) {
                result = "false";
                failReason = "AWS EC2 detailed monitoring is disabled.";
                offenders.add(instance.getInstanceId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_13_Scheduled_events_for_EC2(AmazonEC2 ec2Client)  {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.13";
        String description = "Ensure EC2 Instances scheduled for retirement or/and maintenance ";
        Boolean scored = true;
        DescribeInstanceStatusRequest instanceStatusRequest = new DescribeInstanceStatusRequest();
        instanceStatusRequest.setNextToken(null);
        Collection<Filter> filters = new ArrayList<>();
        List<String> dirValue = Arrays.asList("instance-reboot,system-reboot,system-maintenance,instance-retirement,instance-stop");
        filters.add(new Filter("event.code",dirValue));
        instanceStatusRequest.setFilters(filters);
        List<InstanceStatus> instanceStatuses = new ArrayList<>();
        do {
            DescribeInstanceStatusResult instanceStatusResult = ec2Client.describeInstanceStatus(instanceStatusRequest);
            instanceStatuses.addAll(instanceStatusResult.getInstanceStatuses());
                if (instanceStatusResult.getInstanceStatuses().isEmpty()) {
                    instanceStatusRequest.setNextToken(instanceStatusRequest.getNextToken());
                }
                else {
                    break;
                }
        }
        while (instanceStatusRequest.getNextToken() != null);
        for (InstanceStatus instanceStatus1 :instanceStatuses) {
            List<InstanceStatusEvent> events = instanceStatus1.getEvents();
            for (InstanceStatusEvent event : events) {
                if (event.getCode() != null) {
                    result = "false";
                    failReason = " Scheduled Events found for EC2 Instances.";
                    offenders.add(event.getInstanceEventId());
                }
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_14_security_groups(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.14";
        String description = "Ensure EC2 Security groups does not have groups > 50";
        Boolean scored = true;
        DescribeSecurityGroupsResult groupsResult = ec2Client.describeSecurityGroups();
        List<SecurityGroup> securityGroups = groupsResult.getSecurityGroups();
        for (SecurityGroup securityGroup : securityGroups) {
            if (groupsResult.getSecurityGroups().size() > MAXIMUM_NUMBERS_OF_SECURITY_GROUPS){
                result = "false";
                failReason = "found security groups greater than 50";
                offenders.add(securityGroup.getGroupName());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_15_termination_protection_for_ec2_instances(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.15";
        String description = "Ensure Termination protection is enabled for ec2 instance";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setNextToken(null);
        List<Instance> instances = new ArrayList<>();
        do {
            DescribeInstancesResult instancesResult = ec2Client.describeInstances(request);
            List<Reservation> reservations = instancesResult.getReservations();
            for (Reservation reservation : reservations) {
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()) {
                request.setNextToken(instancesResult.getNextToken());
            }
            else {
                break;
            }
        }
        while (request.getNextToken() != null);
        for (Instance instance : instances) {
            DescribeInstanceAttributeRequest instanceAttributeRequest = new DescribeInstanceAttributeRequest();
            instanceAttributeRequest.setInstanceId(instance.getInstanceId());
            instanceAttributeRequest.setAttribute("disableApiTermination");
            DescribeInstanceAttributeResult instanceAttributeResult = ec2Client.describeInstanceAttribute(instanceAttributeRequest);
            InstanceAttribute attribute = instanceAttributeResult.getInstanceAttribute();
            if (!attribute.getDisableApiTermination()) {
                result = "false";
                failReason = "Termination protection is not enabled for ec2 instance ";
                offenders.add(instance.getInstanceId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_16_netbios_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.16";
        String description = "Ensure EC2 security group should not allow unrestricated access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        List<String> cidr = new ArrayList<>();
        cidr.add("0.0.0.0/0");
        cidr.add("::0");
        List<String > from_port = Arrays.asList("137,138,139");
        List<String> to_port = Arrays.asList("137,138,139");
        filters.add(new Filter("ip-permission.from-port",from_port));
        filters.add(new Filter("ip-permission.to-port",to_port));
        filters.add(new Filter("ip-permission.cidr",cidr));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "EC2 security group is allowing unrestricated access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_17_outbound_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.17";
        String description = "Ensure Unrestricted Outbound Access Should Not Be Allowed.";
        Boolean scored = true;
        DescribeSecurityGroupsRequest request = new DescribeSecurityGroupsRequest();
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(request);
        List<SecurityGroup > groups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : groups) {
            if (!securityGroup.getIpPermissionsEgress().isEmpty()) {
                result = "false";
                failReason  = "found unrestricated outbound access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_19_ec2_instance_using_iam_roles(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.19";
        String description = "Ensure EC2 should using iam roles to sign API requests";
        Boolean scored = true;
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        request.setNextToken(null);
        List<Instance> instances = new ArrayList<>();
        do {
            DescribeInstancesResult instancesResult = ec2Client.describeInstances(request);
            List<Reservation> reservations = instancesResult.getReservations();
            for (Reservation reservation : reservations) {
                instances.addAll(reservation.getInstances());
            }
            if (reservations.isEmpty()) {
                request.setNextToken(instancesResult.getNextToken());
            }
            else {
                break;
            }
        }
        while (request.getNextToken() != null) ;
            for (Instance instance : instances) {
                if (instance.getIamInstanceProfile() == null) {
                    result = "false";
                    failReason ="not found ec2 instances running on IAM roles";
                    offenders.add(instance.getInstanceId());
                }
            }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_20_cifs_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.20";
        String description = "Ensure EC2 security group should not allow unrestricated CIFS access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        List<String> cidr = new ArrayList<>();
        cidr.add("0.0.0.0/0");
        cidr.add("::0");
        List<String > from_port = Arrays.asList("445");
        List<String> to_port = Arrays.asList("445");
        filters.add(new Filter("ip-permission.from-port",from_port));
        filters.add(new Filter("ip-permission.to-port",to_port));
        filters.add(new Filter("ip-permission.cidr",cidr));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "EC2 security group is allowing unrestricated  CIFS access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_21_icmp_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.21";
        String description = "Ensure EC2 security group should not allow unrestricated IMPS access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        List<String> cidr = Collections.singletonList("0.0.0.0/0");
        List<String> ipv6_cidr = Collections.singletonList("::/0");
        List<String > protocol = Collections.singletonList("icmp");
        filters.add(new Filter("ip-permission.protocol",protocol));
        filters.add(new Filter("ip-permission.cidr",cidr));
        filters.add(new Filter("ip-permission.ipv6-cidr",ipv6_cidr));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "EC2 security group is allowing unrestricated ICMP access";
                offenders.add(securityGroup.getGroupName());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_24_mongo_db_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.24";
        String description = "Ensure EC2 security group should not allow unrestricated mongo DB access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("27017")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("27017")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated mongo DB access";
                offenders.add(securityGroup.getGroupName());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_25_MSSQL_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.25";
        String description = "Ensure EC2 security group should not allow unrestricated MS SQL access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("1433")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("1433")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated MS SQL access";
                offenders.add(securityGroup.getGroupName());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_26_My_SQL_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.26";
        String description = "Ensure EC2 security group should not allow unrestricated My SQL access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("3306")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("3306")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated My SQL access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_27_oracle_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.27";
        String description = "Ensure EC2 security group should not allow unrestricated oracle access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("1521")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("1521")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated oracle access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_29_Postgre_SQL_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.29";
        String description = "Ensure EC2 security group should not allow unrestricated postgre SQL access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("5432")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("5432")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated postgre SQL access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }

    public Response control_1_30_rdp_access(AmazonEC2 ec2Client) {
        String result = "true";
        String failReason = "";
        List<String> offenders = new ArrayList<>();
        String control = "1.30";
        String description = "Ensure EC2 security group should not allow unrestricated RDP access";
        Boolean scored = true;
        DescribeSecurityGroupsRequest securityGroupsRequest = new DescribeSecurityGroupsRequest();
        Collection<Filter> filters = new ArrayList<>();
        filters.add(new Filter("ip-permission.from-port", Collections.singletonList("135")));
        filters.add(new Filter("ip-permission.to-port", Collections.singletonList("3389")));
        filters.add(new Filter("ip-permission.ipv6-cidr", Collections.singletonList("::/0")));
        filters.add(new Filter("ip-permission.cidr", Collections.singletonList("0.0.0.0/0")));
        securityGroupsRequest.setFilters(filters);
        DescribeSecurityGroupsResult securityGroupsResult = ec2Client.describeSecurityGroups(securityGroupsRequest);
        List<SecurityGroup> securityGroups = new ArrayList<>(securityGroupsResult.getSecurityGroups());
        for (SecurityGroup securityGroup : securityGroups) {
            if (securityGroup.getGroupName() != null) {
                result = "false";
                failReason = "found EC2 security group that is allowing unrestricated RDP access";
                offenders.add(securityGroup.getGroupId());
            }
        }
        return new Response(result, failReason, offenders, scored, description, control);
    }
}
