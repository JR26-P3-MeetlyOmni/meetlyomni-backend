resource "aws_iam_role" "task_role" {
    name = "${var.project}-ecs-task-role"
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = {
            Service = "ecs-tasks.amazonaws.com"
            }
        }
        ]
    })
  
}

resource "aws_iam_role_policy" "task_role_policy" {
    name = "${var.project}-ecs-task-role-policy"
    role = aws_iam_role.task_role.id
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Action = [
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath",
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:CreateLogGroup",
            "logs:DescribeLogStreams"

            ]
            Effect   = "Allow"
            Resource = "*"
        },
        {
            Action = [
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage"
            ]
            Effect   = "Allow"
            Resource = "*"
        },
        {
            Action = [
            "logs:CreateLogGroup"
            ]
            Effect   = "Allow"
            Resource = "*"
        }
        ]
    })
  
}
