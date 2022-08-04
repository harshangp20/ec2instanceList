package org.lambda.model;

import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.s3.AmazonS3;

public class Clients {

    private AmazonEC2 ec2Client;

    private DynamoDB dynamoDB;

    private AmazonS3 s3;

    public Clients() {
    }

    public Clients(AmazonEC2 ec2Client, DynamoDB dynamoDB, AmazonS3 s3) {
        this.ec2Client = ec2Client;
        this.dynamoDB = dynamoDB;
        this.s3 = s3;

    }

    public AmazonEC2 getEc2Client() {
        return ec2Client;
    }

    public void setEc2Client(AmazonEC2 ec2Client) {
        this.ec2Client = ec2Client;
    }

    public DynamoDB getDynamoDB() {
        return dynamoDB;
    }

    public void setDynamoDB(DynamoDB dynamoDB) {
        this.dynamoDB = dynamoDB;
    }

    public AmazonS3 getS3() {
        return s3;
    }

    public void setS3(AmazonS3 s3) {
        this.s3 = s3;
    }

}
