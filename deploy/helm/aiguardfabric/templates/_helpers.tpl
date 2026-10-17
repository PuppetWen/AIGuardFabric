{{/*
=============================================================================
 templates/_helpers.tpl —— 全 Chart 共享命名/标签/镜像工具

 约定（与 Chart.yaml、values.yaml 对齐）：
   * 基础名 name      = aiguardfabric（.Values.nameOverride 可覆盖）
   * 全名 fullname    = <release>-<name>（.Values.fullnameOverride 可覆盖）
   * 组件名 component = server|ingest|scheduler|web（服务名 agf-<component>）
   * 资源名           = <fullname>-<component>，保证同 release 内唯一且可预测

 环境变量注入（helper 名称以 agf.env.* 出现，但**不是**环境变量）：
   * agf.env.secret.*     生成值 → Secret
   * agf.env.web.url      由 secrets.redisPassword 拼装 AGF_REDIS_URL
=============================================================================
*/}}

{{/* 基础名（默认 chart 名） */}}
{{- define "agf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* 全名：优先 fullnameOverride，否则 <release>-<name>，长度受限 63（K8s label 上限） */}}
{{- define "agf.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* chart 标签值：<name>-<version>，先把 "+" 换成 "_"（label 值不允许 "+"） */}}
{{- define "agf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* ServiceAccount 名 */}}
{{- define "agf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "agf.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* 组件资源名：agf.componentName "server" → <fullname>-server
     调用约定：`(dict "root" $ "component" "server")` —— 因此这里必须走 `.root`，
     不能直接 `include "agf.fullname" .`（`.` 是那个 dict，没有 .Values/.Chart，
     会报 `nil pointer evaluating interface {}.fullnameOverride`；helm lint 实测踩过）。 */}}
{{- define "agf.componentName" -}}
{{- $full := include "agf.fullname" .root -}}
{{- printf "%s-%s" $full .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* 公共标签（所有资源都带） */}}
{{- define "agf.labels" -}}
helm.sh/chart: {{ include "agf.chart" . }}
{{ include "agf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aiguardfabric
{{- end -}}

{{/* 选择器标签（不可变，禁止加入 version/chart 之类会变的键） */}}
{{- define "agf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* 组件标签块：需先 $root := . ; $c := dict "root" . "component" "server" */}}
{{- define "agf.componentLabels" -}}
{{ include "agf.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "agf.componentSelectorLabels" -}}
{{ include "agf.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* 镜像地址：<global.imageRegistry>/<repositoryPrefix>/<repository>:<tag>
     任一可为空；tag 为空回退 Chart.AppVersion（0.1.0，与 compose AGF_IMAGE_TAG 一致） */}}
{{- define "agf.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .componentImage.tag }}{{ $tag = .componentImage.tag }}{{ end -}}
{{- $repo := printf "%s/%s" (default "aiguardfabric" .Values.image.repositoryPrefix) .componentImage.repository -}}
{{- if .Values.global.imageRegistry -}}
{{- printf "%s/%s:%s" (trimSuffix "/" .Values.global.imageRegistry) $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{/* 镜像拉取策略：组件级 > 全局 */}}
{{- define "agf.imagePullPolicy" -}}
{{- default .Values.image.pullPolicy .componentImage.pullPolicy -}}
{{- end -}}

{{/* 镜像拉取密钥：组件级非空用组件级，否则用全局 */}}
{{- define "agf.imagePullSecrets" -}}
{{- $secrets := .Values.global.imagePullSecrets -}}
{{- if .componentImagePullSecrets -}}
{{- $secrets = .componentImagePullSecrets -}}
{{- end -}}
{{- if $secrets -}}
imagePullSecrets:
{{- toYaml $secrets | nindent 2 }}
{{- end -}}
{{- end -}}

{{/* Secret 名：优先 existingSecret，否则 <fullname>-secret */}}
{{- define "agf.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "agf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Secret 键名：允许 existingSecretKeys 覆盖（对齐客户既有 Secret 的键名） */}}
{{- define "agf.secretKey" -}}
{{- $key := .key -}}
{{- $map := .root.Values.secrets.existingSecretKeys | default dict -}}
{{- if hasKey $map $key -}}
{{- index $map $key -}}
{{- else -}}
{{- $key -}}
{{- end -}}
{{- end -}}

{{/* ConfigMap 名 */}}
{{- define "agf.configMapName" -}}
{{- printf "%s-config" (include "agf.fullname" .) -}}
{{- end -}}

{{/* 证据卷 PVC 名 */}}
{{- define "agf.evidenceClaimName" -}}
{{- if .Values.volumes.evidence.existingClaim -}}
{{- .Values.volumes.evidence.existingClaim -}}
{{- else -}}
{{- printf "%s-evidence" (include "agf.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* 服务账户与 Pod 级安全上下文（供各 Deployment 复用） */}}
{{- define "agf.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}

{{/*
  校验：必须提供密钥来源。
  规则：若 secrets.existingSecret 为空，则 jwtSecret / masterKeyBase64 / pgPassword / s3SecretKey
        必须全部非空；否则 fail（避免渲染出无法启动或含弱默认密钥的清单）。
  调用：{{- include "agf.validateSecrets" . -}}
*/}}
{{- define "agf.validateSecrets" -}}
{{- if not .Values.secrets.existingSecret -}}
{{- $missing := list -}}
{{- if not .Values.secrets.pgPassword }}{{ $missing = append $missing "secrets.pgPassword" }}{{ end -}}
{{- if not .Values.secrets.jwtSecret }}{{ $missing = append $missing "secrets.jwtSecret" }}{{ end -}}
{{- if not .Values.secrets.masterKeyBase64 }}{{ $missing = append $missing "secrets.masterKeyBase64" }}{{ end -}}
{{- if not .Values.secrets.s3SecretKey }}{{ $missing = append $missing "secrets.s3SecretKey" }}{{ end -}}
{{- if $missing -}}
{{- fail (printf "AIGuardFabric: 缺少密钥来源。请二选一：(A) 设置 secrets.existingSecret 指向外部 Secret；(B) 在私密值文件中提供 %s。禁止使用明文默认密钥（安全基线 §2.6）。" (join "、" $missing)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* JWT 密钥最小长度校验（>=32 字节，与 .env.example 注释一致） */}}
{{- define "agf.validateJwtLength" -}}
{{- if and (not .Values.secrets.existingSecret) .Values.secrets.jwtSecret -}}
{{- if lt (len .Values.secrets.jwtSecret) 32 -}}
{{- fail (printf "AIGuardFabric: secrets.jwtSecret 长度 %d < 32，不满足安全基线（AGF_JWT_SECRET 需 >=32 字节）" (len .Values.secrets.jwtSecret)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Redis URL 注入策略：
    * 无口令（默认/内网信任域）：直接用 config.AGF_REDIS_URL（如 redis://<fullname>-redis:6379/0）
    * 有口令：Secret 里提供 AGF_REDIS_URL（含口令段），本 helper 只做文档说明，
      实际注入见 templates/secret.yaml 的 redisUrl 键 —— 避免把口令明文写进 ConfigMap。
  调用：{{ include "agf.redisUrl" . }} 返回不含口令的连接串（供 ConfigMap 使用）
*/}}
{{- define "agf.redisUrl" -}}
{{- .Values.config.AGF_REDIS_URL -}}
{{- end -}}

{{/* Prometheus 抓取目标注解（供无 ServiceMonitor CRD 的集群用 pod annotation 抓取） */}}
{{- define "agf.prometheusAnnotations" -}}
{{- if .Values.config.AGF_PROMETHEUS_ENABLED -}}
{{- if eq (toString .Values.config.AGF_PROMETHEUS_ENABLED) "1" -}}
prometheus.io/scrape: "true"
prometheus.io/port: {{ default .Values.ports.metrics .metricsPort | quote }}
prometheus.io/path: "/metrics"
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  环境变量块（各服务 Deployment 复用）
  调用约定：
    {{- $root := . -}}
    {{- $c := dict "root" $root "component" "server" -}}
    {{- include "agf.env" $c | nindent 12 }}

  顺序（后者覆盖前者）：
    1. 非敏感配置 → 由 ConfigMap 以 envFrom 注入（在 Deployment 里声明）
    2. Secret → 以 secretKeyRef 逐键注入（**只注入该服务需要的键**）
    3. 服务级 env 覆盖（.Values.<component>.env）
    4. 服务级 extraEnv 原样追加（可引用任意 ConfigMap/Secret/FieldRef）
*/}}
{{- define "agf.env" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $svc := index $root.Values $component -}}
{{- $secretName := include "agf.secretName" $root -}}
# ---- 来自 Secret 的敏感变量（键名可被 secrets.existingSecretKeys 重映射）----
{{- range $k := (list "AGF_PG_PASSWORD" "AGF_JWT_SECRET" "AGF_MASTER_KEY_BASE64" "AGF_S3_ACCESS_KEY" "AGF_S3_SECRET_KEY" "AGF_CLICKHOUSE_PASSWORD" "AGF_BOOTSTRAP_ADMIN_PASSWORD") }}
- name: {{ $k }}
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: {{ include "agf.secretKey" (dict "root" $root "key" $k) }}
      optional: true
{{- end }}
{{- if $root.Values.secrets.redisPassword }}
- name: AGF_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: {{ include "agf.secretKey" (dict "root" $root "key" "AGF_REDIS_URL") }}
      optional: true
{{- end }}
{{- if eq (toString $root.Values.config.AGF_ALIYUN_ENABLED) "1" }}
# ---- 阿里云凭据（仅在启用时注入；无凭据走 MockAdapter）----
- name: AGF_ALIYUN_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: {{ include "agf.secretKey" (dict "root" $root "key" "AGF_ALIYUN_ACCESS_KEY_ID") }}
      optional: true
- name: AGF_ALIYUN_ACCESS_KEY_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: {{ include "agf.secretKey" (dict "root" $root "key" "AGF_ALIYUN_ACCESS_KEY_SECRET") }}
      optional: true
- name: AGF_ALIYUN_STS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: {{ include "agf.secretKey" (dict "root" $root "key" "AGF_ALIYUN_STS_TOKEN") }}
      optional: true
{{- end }}
# ---- 服务级非敏感覆盖 ----
{{- range $k, $v := $svc.env }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
# ---- 服务级附加变量（原样透传）----
{{- if $svc.extraEnv }}
{{- toYaml $svc.extraEnv }}
{{- end }}
{{- end -}}

{{/*
  探针块：按 type 渲染 tcp/http/exec
  调用：{{- include "agf.probe" (dict "probe" $svc.livenessProbe "svc" $svc "defaultPort" "api" "root" $) }}
*/}}
{{- define "agf.probe" -}}
{{- $p := .probe -}}
{{- $portName := .defaultPort -}}
{{- if $p.port }}{{ $portName = $p.port }}{{ end -}}
{{- if eq (toString $portName) "schedulerHealth" }}{{ $portName = "sched-health" }}{{ end -}}
{{- if eq $p.type "tcp" }}
tcpSocket:
  port: {{ $portName }}
{{- else if eq $p.type "exec" }}
exec:
  command:
{{- toYaml $p.command | nindent 4 }}
{{- else }}
httpGet:
  path: {{ default "/healthz" $p.path }}
  port: {{ $portName }}
  scheme: HTTP
{{- end }}
initialDelaySeconds: {{ default 10 $p.initialDelaySeconds }}
periodSeconds: {{ default 10 $p.periodSeconds }}
timeoutSeconds: {{ default 3 $p.timeoutSeconds }}
failureThreshold: {{ default 3 $p.failureThreshold }}
{{- if $p.successThreshold }}
successThreshold: {{ $p.successThreshold }}
{{- end }}
{{- end -}}

{{/*
  preStop 钩子：distroless 镜像无 shell，故只支持 httpGet（K8s 原生方式）
  调用：{{- include "agf.preStop" (dict "hook" $svc.preStop) | nindent 12 }}
*/}}
{{- define "agf.preStop" -}}
{{- if and .hook .hook.enabled }}
lifecycle:
  preStop:
    httpGet:
      path: {{ default "/healthz" .hook.httpGet.path }}
      port: {{ .hook.httpGet.port }}
      scheme: HTTP
{{- end }}
{{- end -}}
