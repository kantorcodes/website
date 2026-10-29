---
title: "Catch Kubernetes privilege regressions before applying a manifest"
seoTitle: "Catch Kubernetes privilege regressions in manifest reviews"
seoDescription: "A small, tested Python diff catches lost workload security settings before a Kubernetes deployment is applied."
datePublished: 2026-10-29T00:00:00.000Z
slug: detect-kubernetes-security-context-regressions
author: michael-kantor
tags: ["kubernetes", "security", "devops", "ai"]
draft: false
---

A deployment update can look harmless in a pull request. An image tag changes, a resource request moves, and the reviewer sees another routine release. But the same edit can remove a protective setting or change which credentials a workload receives.

That risk is especially easy to miss when a coding agent edits YAML alongside ordinary application code. There is no reason to treat an agent's explanation of its own edit as an independent security check.

This walkthrough builds a small, reproducible review-time comparison. It looks for security settings that were explicitly restrictive in the baseline and became less restrictive or unspecified in the proposed manifest. It does **not** contact a Kubernetes cluster, evaluate all admission rules, or prove that a workload is safe.

## Start with one known-good workload

Save this as **baseline.yaml**:

~~~yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: invoice-worker
  namespace: jobs
spec:
  selector:
    matchLabels:
      app: invoice-worker
  template:
    metadata:
      labels:
        app: invoice-worker
    spec:
      automountServiceAccountToken: false
      containers:
        - name: worker
          image: example.invalid/worker:v1
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
~~~

The image URL is an inert example, not a runnable container or a real registry. The three container settings and the service account token choice are the baseline we want to preserve. These are explicit settings, not inferred defaults.

Now save **proposal.yaml**:

~~~yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: invoice-worker
  namespace: jobs
spec:
  selector:
    matchLabels:
      app: invoice-worker
  template:
    metadata:
      labels:
        app: invoice-worker
    spec:
      automountServiceAccountToken: true
      containers:
        - name: worker
          image: example.invalid/worker:v2
          securityContext:
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: true
            runAsNonRoot: true
~~~

An image revision is expected. The token-mount change and the privilege-escalation change need independent review. A conventional textual diff contains both kinds of change, but it does not classify them.

## Compare the proposed settings with the baseline

Install the single YAML parser dependency in a throwaway virtual environment:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install PyYAML==6.0.3
~~~

Save the following as **audit.py**. The script examines ordinary Pods, workloads with a pod template, Jobs, and CronJobs. It compares named containers inside the same kind, namespace and workload name. A removed workload or new container becomes a review condition rather than disappearing silently.

~~~python
#!/usr/bin/env python3
"""Review-time regression check for already-rendered Kubernetes YAML.
Illustrative, not a cluster policy or complete manifest validator.
Requires PyYAML 6.0.3.
"""
import sys
from pathlib import Path
import yaml


def pod_spec(doc):
    spec = doc.get('spec', {})
    kind = doc.get('kind')
    if kind == 'Pod':
        return spec
    if kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job'):
        return spec.get('template', {}).get('spec', {})
    if kind == 'CronJob':
        return (spec.get('jobTemplate', {}).get('spec', {})
                .get('template', {}).get('spec', {}))
    return None


def load(path):
    by_key = {}
    with Path(path).open(encoding='utf-8') as fh:
        for document in yaml.safe_load_all(fh):
            if not isinstance(document, dict):
                continue
            pod = pod_spec(document)
            if pod is None:
                continue
            meta = document.get('metadata') or {}
            key = (document.get('kind'), meta.get('namespace', 'default'),
                   meta.get('name'))
            if not key[2] or key in by_key:
                raise ValueError(f'missing or duplicate workload name: {key}')
            by_key[key] = pod
    return by_key


def regressions(before, after):
    issues = []
    for key, old in sorted(before.items()):
        label = '/'.join(key)
        new = after.get(key)
        if new is None:
            issues.append(f'{label}: workload removed; review separately')
            continue
        for flag, safe in (('automountServiceAccountToken', False),
                           ('hostNetwork', False),
                           ('hostPID', False)):
            if old.get(flag) == safe and new.get(flag) != safe:
                issues.append(f'{label}: {flag} lost explicit {safe}')
        old_containers = {c['name']: c for c in old.get('containers', [])}
        new_containers = {c['name']: c for c in new.get('containers', [])}
        for name, prev in sorted(old_containers.items()):
            tag = f'{label}/{name}'
            if name not in new_containers:
                issues.append(f'{tag}: container removed; review separately')
                continue
            old_sc = prev.get('securityContext') or {}
            new_sc = new_containers[name].get('securityContext') or {}
            for flag, safe in (('allowPrivilegeEscalation', False),
                               ('readOnlyRootFilesystem', True),
                               ('runAsNonRoot', True)):
                if old_sc.get(flag) == safe and new_sc.get(flag) != safe:
                    issues.append(f'{tag}: {flag} lost explicit {safe}')
            if old_sc.get('privileged') is not True and new_sc.get('privileged') is True:
                issues.append(f'{tag}: privileged became true')
        for added in sorted(new_containers.keys() - old_containers.keys()):
            issues.append(f'{label}/{added}: new container; review separately')
    return issues


def main():
    if len(sys.argv) != 3:
        print('usage: python audit.py baseline.yaml proposal.yaml', file=sys.stderr)
        return 2
    try:
        base, proposal = load(sys.argv[1]), load(sys.argv[2])
        issues = regressions(base, proposal)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    if issues:
        for item in issues:
            print('REVIEW:', item)
        print(f'FAIL: {len(issues)} regressions / review conditions')
        return 1
    print('PASS: no configured regressions found in matching workloads')
    return 0


if __name__ == '__main__':
    sys.exit(main())
~~~

The zero-exit result means only that this particular comparison found no configured regression. A one-exit result means at least one issue needs review. Two means a usage or parsing error. A CI job should treat both nonzero results as a failed gate until a reviewer decides what to change.

## Run a clean control and a deliberate regression

The following output was recorded with Python **3.13.5** and PyYAML **6.0.3** using these two example files:

~~~text
$ python3 audit.py baseline.yaml baseline.yaml
PASS: no configured regressions found in matching workloads
$ echo $?
0

$ python3 audit.py baseline.yaml proposal.yaml
REVIEW: Deployment/jobs/invoice-worker: automountServiceAccountToken lost explicit False
REVIEW: Deployment/jobs/invoice-worker/worker: allowPrivilegeEscalation lost explicit False
FAIL: 2 regressions / review conditions
$ echo $?
1
~~~

The clean baseline and deliberately modified proposal provide useful positive and negative controls. They are still two synthetic YAML files. They are not findings from a running application, a security benchmark, or a proof about an actual cluster.

To add this to a GitHub Actions workflow, produce the *rendered* old and new manifests first, then run the comparison on those files:

~~~yaml
- name: Review workload setting regressions
  run: python3 audit.py baseline.yaml proposal.yaml
~~~

This is a fragment of a job, not a standalone workflow. It assumes the earlier steps have installed the pinned parser and have checked out the script and both manifests. If Helm, Kustomize or another generator produces your deployment, compare the rendered output, not two templates that might expand differently.

## What the check cannot tell you

There are several boundaries worth keeping visible:

- A missing service account setting is **unknown**, not automatically an active token mount. ServiceAccount settings and cluster configuration affect the result. The check reports removal of an explicit false value, not proof that a token was exposed.
- A changed security context is a review signal, not evidence of compromise. Kubernetes can reject, default or mutate a workload through admission mechanisms.
- This script does not validate Kubernetes schemas, role bindings, namespace authorization, Pod Security Admission, mounted secrets, network policy, init or ephemeral containers, or nested custom resources. It only compares the fields shown.
- A newly introduced workload is not inspected by this baseline-only comparison. In a real pipeline, add a separate policy covering newly added resources.
- Parsing YAML locally does not guarantee the same objects are submitted to the API server. Use the exact deploy artifact, validate it independently and protect the CI identity that can approve or apply it.

The sensible workflow is layered: use this diff to flag unexpected changes early, review the actual rendered manifests, and rely on Kubernetes admission and runtime controls for the final enforcement boundary. It is particularly useful when automated coding tools make many changes quickly, because it checks the files they produced rather than trusting their summary.

The Kubernetes documentation covers [container security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/), [service account token configuration](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) and [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). These are the authoritative references for a deployment policy.

The small script here is intentionally narrow and reproducible. Keep its pass/fail labels equally narrow.

---
Michael Kantor is President of HOL and CEO of Moonscape Labs Inc., HOL's commercial operator. This example does not evaluate or promote a HOL product.
