{# The daemon refuses to start with no reflector to run, so "enabled" must mean the same thing here as
   in netflector_enabled(): the service is on AND at least one entry is on. Keying only on the global
   switch would arm a service whose generated configuration has no [reflectors.*] table at all. #}
{% set armed = [] %}
{% if helpers.exists('OPNsense.Netflector.general.enabled') and OPNsense.Netflector.general.enabled == '1' %}
{%   if helpers.exists('OPNsense.Netflector.reflectors.reflector') %}
{%     for entry in helpers.toList('OPNsense.Netflector.reflectors.reflector') %}
{%       if entry.enabled|default('0') == '1' %}
{%         do armed.append(entry.name) %}
{%       endif %}
{%     endfor %}
{%   endif %}
{% endif %}
{% if armed %}
netflector_enable="YES"
{% else %}
netflector_enable="NO"
{% endif %}
