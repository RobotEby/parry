data "aws_iam_policy_document" "ecs_tasks_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

locals {
  secret_arns = compact([
    var.parry_admin_token_secret_arn,
    var.redis_auth_token_secret_arn
  ])

  container_secrets = concat(
    var.parry_admin_token_secret_arn != "" ? [
      {
        name      = "PARRY_ADMIN_TOKEN"
        valueFrom = var.parry_admin_token_secret_arn
      }
    ] : [],
    var.redis_auth_token_secret_arn != "" ? [
      {
        name      = "REDIS_AUTH_TOKEN"
        valueFrom = var.redis_auth_token_secret_arn
      }
    ] : []
  )
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-cluster"
  })
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  count = length(local.secret_arns) > 0 ? 1 : 0

  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "ssm:GetParameters",
      "ssm:GetParameter"
    ]
    resources = local.secret_arns
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  count = length(local.secret_arns) > 0 ? 1 : 0

  name   = "${var.name_prefix}-ecs-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets[0].json
}

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role.json

  tags = var.tags
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.name_prefix}-demo-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name      = "parry-demo-api"
      image     = var.container_image
      essential = true

      portMappings = [
        {
          containerPort = var.app_port
          hostPort      = var.app_port
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "NODE_ENV"
          value = "production"
        },
        {
          name  = "PORT"
          value = tostring(var.app_port)
        },
        {
          name  = "PARRY_STORE"
          value = "redis"
        },
        {
          name  = "PARRY_PRESET"
          value = "recommended"
        },
        {
          name  = "REDIS_URL"
          value = "rediss://${var.redis_endpoint}:6379"
        },
        {
          name  = "REDIS_TLS"
          value = "true"
        }
      ]

      secrets = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.cloudwatch_log_group_name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "parry"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "this" {
  name            = "${var.name_prefix}-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = "parry-demo-api"
    container_port   = var.app_port
  }

  tags = var.tags
}
