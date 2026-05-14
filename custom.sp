# --- BENCHMARK ---

benchmark "aws_security_compliance_benchmark" {
  title       = "AWS Security Standard Compliance"
  description = "Custom benchmark for monitoring infrastructure security posture."
  children = [
    control.ebs_encryption_by_default_enabled,
    control.unattached_security_groups,
    control.efs_encryption_at_rest_enabled,
    control.ebs_attached_volume_encryption_enabled,
    control.guardduty_enabled,
    control.vpc_flow_logs_enabled,
    control.restricted_ingress_ports
  ]
}

# --- DASHBOARD ---

dashboard "aws_compliance_dashboard" {
  title = "AWS Compliance Dashboard"

  container {
    card {
      query = query.compliance_summary_total
      width = 3
    }
    card {
      query = query.compliance_summary_alarm
      width = 3
    }
  }

  container {
    table {
      title = "Storage & Encryption Compliance"
      query = query.storage_compliance_drilldown
    }

    table {
      title = "Network & Threat Detection Status"
      query = query.network_compliance_drilldown
    }
  }
}

# --- CONTROLS ---

control "ebs_encryption_by_default_enabled" {
  title       = "EBS encryption by default should be enabled"
  description = "Checks if EBS encryption by default is enabled for the AWS account in the current region."
  query       = query.ebs_encryption_by_default_enabled
}

control "unattached_security_groups" {
  title       = "All non-default security groups should be attached to at least one ENI"
  description = "Checks if all non-default security groups are attached to at least one ENI."
  query       = query.unattached_security_groups
}

control "efs_encryption_at_rest_enabled" {
  title       = "EFS file systems should be encrypted at rest"
  description = "Checks if EFS file systems are encrypted at rest."
  query       = query.efs_encryption_at_rest_enabled
}

control "ebs_attached_volume_encryption_enabled" {
  title       = "Attached EBS volumes should be encrypted"
  description = "Checks if attached EBS volumes are encrypted."
  query       = query.ebs_attached_volume_encryption_enabled
}

control "guardduty_enabled" {
  title       = "Amazon GuardDuty should be enabled"
  description = "Checks if Amazon GuardDuty is enabled in the account/region."
  query       = query.guardduty_enabled
}

control "vpc_flow_logs_enabled" {
  title       = "VPC flow logs should be enabled on every VPC"
  description = "Checks if VPC Flow Logs are enabled on every VPC."
  query       = query.vpc_flow_logs_enabled
}

control "restricted_ingress_ports" {
  title       = "Security groups should restrict ingress on unauthorized ports"
  description = "Checks for unrestricted incoming traffic (0.0.0.0/0) on non-web ports."
  query       = query.restricted_ingress_ports
}

# --- FIXED QUERIES ---

query "ebs_encryption_by_default_enabled" {
  sql = <<-EOQ
    select
      'arn:aws:ec2:' || region || ':' || account_id as resource,
      case
        when ebs_encryption_by_default_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when ebs_encryption_by_default_enabled then 'EBS encryption by default is enabled.'
        else 'EBS encryption by default is disabled.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_regional_settings;
  EOQ
}

query "unattached_security_groups" {
  sql = <<-EOQ
    with attached_sgs as (
      select
        distinct sg_id
      from
        aws_vpc_network_interface,
        jsonb_array_elements(groups) as g
        left join lateral (select g ->> 'GroupId' as sg_id) as t on true
    )
    select
      sg.group_id as resource,
      case
        when sg.group_name = 'default' then 'ok'
        when a.sg_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when sg.group_name = 'default' then sg.group_id || ' is a default security group.'
        when a.sg_id is null then sg.group_id || ' is not attached to any ENI.'
        else sg.group_id || ' is attached to an ENI.'
      end as reason,
      region,
      account_id
    from
      aws_vpc_security_group as sg
      left join attached_sgs as a on sg.group_id = a.sg_id;
  EOQ
}

query "efs_encryption_at_rest_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case when encrypted then 'ok' else 'alarm' end as status,
      case when encrypted then title || ' is encrypted.' else title || ' is not encrypted.' end as reason,
      region, account_id
    from aws_efs_file_system;
  EOQ
}

query "ebs_attached_volume_encryption_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case when encrypted then 'ok' else 'alarm' end as status,
      case when encrypted then title || ' is encrypted.' else title || ' is unencrypted.' end as reason,
      region, account_id
    from aws_ebs_volume where state = 'in-use';
  EOQ
}

query "guardduty_enabled" {
  sql = <<-EOQ
    with detectors as (
      select region, count(*) as count from aws_guardduty_detector group by region
    )
    select
      'arn:aws:guardduty:' || r.name || ':' || r.account_id as resource,
      case when d.count > 0 then 'ok' else 'alarm' end as status,
      case when d.count > 0 then 'GuardDuty enabled.' else 'GuardDuty disabled.' end as reason,
      r.name as region, r.account_id
    from aws_region as r left join detectors as d on d.region = r.name;
  EOQ
}

query "vpc_flow_logs_enabled" {
  sql = <<-EOQ
    with vpc_logs as (
      select resource_id, count(*) as log_count from aws_vpc_flow_log where resource_id like 'vpc-%' group by resource_id
    )
    select
      v.vpc_id as resource,
      case when l.log_count > 0 then 'ok' else 'alarm' end as status,
      case when l.log_count > 0 then v.vpc_id || ' has flow logs.' else v.vpc_id || ' has no flow logs.' end as reason,
      region, account_id
    from aws_vpc as v left join vpc_logs as l on v.vpc_id = l.resource_id;
  EOQ
}

query "restricted_ingress_ports" {
  sql = <<-EOQ
    select
      group_id as resource,
      case
        when cidr_ipv4 = '0.0.0.0/0' and from_port not in (80, 443) then 'alarm'
        else 'ok'
      end as status,
      case
        when cidr_ipv4 = '0.0.0.0/0' and from_port not in (80, 443) then 'Unrestricted access on port ' || from_port
        else 'Restricted or authorized port.'
      end as reason,
      region, account_id
    from aws_vpc_security_group_rule where type = 'ingress';
  EOQ
}

# --- DASHBOARD SUMMARY QUERIES ---

query "compliance_summary_total" {
  sql = "select 'Security Groups' as label, count(*) as value from aws_vpc_security_group;"
}

query "compliance_summary_alarm" {
  sql = "select 'Unencrypted Volumes' as label, count(*) as value, 'alert' as type from aws_ebs_volume where not encrypted;"
}

query "storage_compliance_drilldown" {
  sql = "select arn as resource, case when encrypted then 'ok' else 'alarm' end as status, region from aws_ebs_volume limit 5;"
}

query "network_compliance_drilldown" {
  sql = "select vpc_id as resource, region, account_id from aws_vpc limit 5;"
}