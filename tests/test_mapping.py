import dataclasses

import pytest
from factories import vulnerability_report

from trivy_secobserve.config import Settings
from trivy_secobserve.mapping import (
    render,
    resolve_target,
    template_values,
    upload_filename,
    validate_templates,
)

SETTINGS = Settings(cluster_name="test-cluster")


def values(**kwargs):
    return template_values("test-cluster", vulnerability_report(**kwargs))


def test_template_values():
    v = values()
    assert v["namespace"] == "shop-prod"
    assert v["registry"] == "registry.example.com"
    assert v["repository"] == "demo/app"
    assert v["image_name"] == "app"
    assert v["resource_kind"] == "ReplicaSet"
    assert v["container"] == "app"


def test_defaults_namespace_as_product_image_as_service():
    target = resolve_target(SETTINGS, values(), {}, {})
    assert (target.product, target.branch, target.service, target.product_group) == ("shop-prod", "", "app", "")


def test_annotations_override_product_group_branch():
    annotations = {
        "secobserve.io/product": "Shop Prod",
        "secobserve.io/product-group": "Pimcore Installationen",
        "secobserve.io/branch": "prod",
    }
    target = resolve_target(SETTINGS, values(), {}, annotations)
    assert (target.product, target.product_group, target.branch) == ("Shop Prod", "Pimcore Installationen", "prod")


def test_default_product_group_and_templates():
    settings = dataclasses.replace(
        SETTINGS,
        product_group="Default Group",
        product_name_template="{cluster} / {namespace}",
        service_name_template="{resource_name}-{container}",
        branch_name_template="{tag}",
    )
    target = resolve_target(settings, values(), {}, {})
    assert target.product == "test-cluster / shop-prod"
    assert target.service == "app-7d9f-app"
    assert target.branch == "1.0.0"
    assert target.product_group == "Default Group"


def test_excluded_and_opted_out_namespaces():
    assert resolve_target(SETTINGS, values(namespace="kube-system"), {}, {}) is None
    assert resolve_target(SETTINGS, values(), {"secobserve.io/enabled": "false"}, {}) is None


def test_require_namespace_label():
    settings = dataclasses.replace(SETTINGS, require_namespace_label=True)
    assert resolve_target(settings, values(), {}, {}) is None
    assert resolve_target(settings, values(), {"secobserve.io/enabled": "true"}, {}) is not None
    assert resolve_target(settings, values(), {}, {"secobserve.io/product": "X"}) is not None


@pytest.mark.parametrize("template", ["{namespace.__class__}", "{namespace[0]}", "{unknown}", "{0}"])
def test_templates_cannot_reach_into_objects(template):
    with pytest.raises((ValueError, KeyError, IndexError)):
        render(template, values())


def test_validate_templates_rejects_bad_config():
    with pytest.raises(ValueError):
        validate_templates(dataclasses.replace(SETTINGS, service_name_template="{evil}"))


def test_upload_filename_is_stable_and_safe():
    target = resolve_target(SETTINGS, values(), {}, {"secobserve.io/product": "Shop Prod"})
    assert upload_filename(SETTINGS, target) == "trivy-operator_test-cluster_app.cdx.json"
    weird = dataclasses.replace(target, service="a b/c")
    assert upload_filename(SETTINGS, weird) == "trivy-operator_test-cluster_a-b-c.cdx.json"


def _rule_settings(rules_json, monkeypatch, **env):
    monkeypatch.setenv("NAMESPACE_RULES", rules_json)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings.from_env()


def test_namespace_rules_map_groups_of_namespaces(monkeypatch):
    settings = _rule_settings(
        '[{"match": "argocd|ingress-nginx|secobserve.*", "productGroup": "CORS Infrastruktur"},'
        ' {"match": "(.*)-staging", "product": "{namespace} (staging)", "branch": "staging"},'
        ' {"match": "ingress-.*", "productGroup": "never reached"}]',
        monkeypatch,
        PRODUCT_GROUP="Pimcore Installationen",
    )
    infra = resolve_target(settings, values(namespace="ingress-nginx"), {}, {})
    assert (infra.product, infra.product_group, infra.branch) == ("ingress-nginx", "CORS Infrastruktur", "")
    assert resolve_target(settings, values(namespace="secobserve-operator"), {}, {}).product_group == (
        "CORS Infrastruktur"
    )
    staging = resolve_target(settings, values(namespace="shop-staging"), {}, {})
    assert (staging.product, staging.product_group, staging.branch) == (
        "shop-staging (staging)",
        "Pimcore Installationen",  # not set in the rule: global default
        "staging",
    )
    customer = resolve_target(settings, values(namespace="shop-prod"), {}, {})
    assert (customer.product, customer.product_group) == ("shop-prod", "Pimcore Installationen")
    assert resolve_target(settings, values(namespace="argocd-extra"), {}, {}).product_group == (
        "Pimcore Installationen"  # full match only
    )


def test_annotations_beat_namespace_rules(monkeypatch):
    settings = _rule_settings('[{"match": "argocd", "productGroup": "CORS Infrastruktur"}]', monkeypatch)
    annotations = {"secobserve.io/product-group": "Special", "secobserve.io/product": "X"}
    target = resolve_target(settings, values(namespace="argocd"), {}, annotations)
    assert (target.product, target.product_group) == ("X", "Special")


def test_rule_can_clear_the_default_group(monkeypatch):
    settings = _rule_settings('[{"match": "sandbox", "productGroup": ""}]', monkeypatch, PRODUCT_GROUP="Pimcore")
    assert resolve_target(settings, values(namespace="sandbox"), {}, {}).product_group == ""


@pytest.mark.parametrize(
    "rules",
    [
        '{"match": "x"}',  # not a list
        '[{"productGroup": "x"}]',  # no match
        '[{"match": "("}]',  # invalid regex
        '[{"match": "x", "group": "y"}]',  # unknown key
        '[{"match": "x", "productGroup": 1}]',  # not a string
    ],
)
def test_invalid_namespace_rules_are_rejected(rules, monkeypatch):
    with pytest.raises(ValueError):
        _rule_settings(rules, monkeypatch)


def test_rule_templates_are_validated(monkeypatch):
    settings = _rule_settings('[{"match": "x", "product": "{secret}"}]', monkeypatch)
    with pytest.raises(ValueError):
        validate_templates(settings)


def test_named_groups_put_namespaces_into_one_product(monkeypatch):
    settings = _rule_settings(
        '[{"match": "argocd|secobserve", "productGroup": "CORS Infrastruktur"},'
        ' {"match": "(?P<project>.+)-(?P<env>prod|staging)", "product": "{project}", "branch": "{env}"}]',
        monkeypatch,
        PRODUCT_GROUP="Pimcore Installationen",
    )
    prod = resolve_target(settings, values(namespace="ske-solar-prod"), {}, {})
    staging = resolve_target(settings, values(namespace="ske-solar-staging"), {}, {})
    assert (prod.product, prod.branch, prod.product_group) == ("ske-solar", "prod", "Pimcore Installationen")
    assert (staging.product, staging.branch) == ("ske-solar", "staging")
    assert prod.service == staging.service == "app"
    # no match: namespace as product, no branch
    other = resolve_target(settings, values(namespace="proofval"), {}, {})
    assert (other.product, other.branch) == ("proofval", "")
    # annotations still win
    annotated = resolve_target(settings, values(namespace="shop-prod"), {}, {"secobserve.io/branch": "live"})
    assert (annotated.product, annotated.branch) == ("shop", "live")
    validate_templates(settings)


def test_unmatched_optional_group_is_empty(monkeypatch):
    settings = _rule_settings(
        '[{"match": "(?P<project>[a-z]+)(-(?P<env>staging))?", "product": "{project}", "branch": "{env}"}]',
        monkeypatch,
    )
    assert resolve_target(settings, values(namespace="shop"), {}, {}).branch == ""
    assert resolve_target(settings, values(namespace="shop-staging"), {}, {}).branch == "staging"


def test_group_names_are_checked(monkeypatch):
    with pytest.raises(ValueError, match="group name"):
        _rule_settings('[{"match": "(?P<Project>.+)"}]', monkeypatch)
    clash = _rule_settings('[{"match": "(?P<namespace>.+)", "product": "{namespace}"}]', monkeypatch)
    with pytest.raises(ValueError, match="template fields already"):
        validate_templates(clash)
    # a group of another rule is not available
    other = _rule_settings('[{"match": "(?P<project>.+)-prod"}, {"match": "x", "product": "{project}"}]', monkeypatch)
    with pytest.raises(ValueError, match="Unknown template field"):
        validate_templates(other)
