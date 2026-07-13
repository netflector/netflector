<?php

/*
 * Copyright (C) 2026 Sergii Bogomolov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Netflector;

use OPNsense\Base\BaseModel;
use Phalcon\Messages\Message;

/**
 * The model's rules, mirroring what the daemon refuses to start with, so the GUI rejects a bad entry
 * against the offending field instead of writing a netflector.toml that fails at startup.
 *
 * This mirroring is a convenience, not the guarantee: it can drift when the daemon's rules change. The
 * authority is the daemon itself, via `configctl netflector check` (netflector --check-config) on the
 * generated file before the service is restarted. Keep both. A rule added here without a matching rule
 * there only annoys the user; a rule there without one here is caught, just later and less precisely.
 */
class Netflector extends BaseModel
{
    /** The protocols an entry may enable. One of them must be on, or the entry reflects nothing. */
    private const PROTOCOLS = ['wol', 'mdns', 'ssdp', 'wsd'];

    /** Families that carry IPv4, and those that carry IPv6. Mirrors AddressFamily::uses_ipv4 / uses_ipv6. */
    private const IPV4_FAMILIES = ['default', 'dual', 'ipv4'];
    private const IPV6_FAMILIES = ['default', 'dual', 'ipv6'];

    /** The daemon's WoL ports when the entry does not name any. */
    private const DEFAULT_WOL_PORTS = ['7', '9'];

    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        foreach ($this->reflectors->reflector->iterateItems() as $entry) {
            if (!$validateFullModel && !$entry->isFieldChanged()) {
                continue;
            }
            $this->validateEntry($entry, $messages);
        }

        // Only enabled entries reach the generated file, so only they can collide there. Checked over
        // every pair regardless of which entry was edited: a collision is a property of the pair, and
        // the entry that creates it is often not the one being saved.
        $active = [];
        foreach ($this->reflectors->reflector->iterateItems() as $entry) {
            if ((string)$entry->enabled === '1') {
                $active[] = $entry;
            }
        }
        foreach ($active as $i => $a) {
            foreach (array_slice($active, $i + 1) as $b) {
                $this->validatePair($a, $b, $messages);
            }
        }

        // Switched on with nothing to reflect is a contradiction: the daemon refuses to start with no
        // reflector at all, so the service is left unarmed and the GUI shows "Enabled" over a daemon
        // that is quietly not running. Rejecting it here is what makes Save, Apply and Validate agree;
        // without it, Validate calls this state an error while Apply accepts it without a word.
        if ((string)$this->general->enabled === '1' && empty($active)) {
            $messages->appendMessage(new Message(
                gettext('Enable at least one reflector, or switch Netflector off. It cannot run with nothing to reflect.'),
                'general.enabled'
            ));
        }

        return $messages;
    }

    private function validateEntry($entry, $messages)
    {
        $ref = $entry->__reference;

        // Reflecting onto the interface a packet arrived on would echo it straight back. Both fields
        // are Required in the model, so emptiness is already reported; the non-empty guard is what
        // stops two blank interfaces ('' === '') from also collecting a bogus "must differ" on top.
        if ((string)$entry->source_if !== '' && (string)$entry->source_if === (string)$entry->target_if) {
            $messages->appendMessage(new Message(
                gettext('The source and target interfaces must differ.'),
                $ref . '.target_if'
            ));
        }

        $enabled = false;
        foreach (self::PROTOCOLS as $protocol) {
            if ((string)$entry->$protocol === '1') {
                $enabled = true;
                break;
            }
        }
        if (!$enabled) {
            $messages->appendMessage(new Message(
                gettext('Enable at least one protocol.'),
                $ref . '.mdns'
            ));
        }

        // DIAL is carried by SSDP's discovery exchange; it cannot stand on its own.
        if ((string)$entry->dial === '1' && (string)$entry->ssdp !== '1') {
            $messages->appendMessage(new Message(
                gettext('The DIAL proxy needs SSDP enabled.'),
                $ref . '.dial'
            ));
        }

        // DIAL proxies HTTP over IPv4 literals only, so an IPv6-only entry can never carry it.
        if ((string)$entry->dial === '1' && !self::usesIpv4((string)$entry->address_family)) {
            $messages->appendMessage(new Message(
                gettext('The DIAL proxy is IPv4-only and cannot run on an IPv6-only reflector.'),
                $ref . '.dial'
            ));
        }

        // Ports without the protocol they belong to are a misconfiguration the daemon rejects.
        if ((string)$entry->wol !== '1' && (string)$entry->wol_ports !== '') {
            $messages->appendMessage(new Message(
                gettext('Wake-on-LAN ports only apply when Wake-on-LAN is enabled.'),
                $ref . '.wol_ports'
            ));
        }
    }

    /**
     * Two enabled entries must not share a name, nor reflect the same protocol's packets twice.
     * Mirrors the daemon's check_conflicts / Reflector::conflicts_with.
     */
    private function validatePair($a, $b, $messages)
    {
        // The non-empty guard is not tolerance of a blank name: name is Required, so a blank one is
        // already reported. It stops two blank names ('' === '') from also collecting "already used",
        // which would point at the wrong problem.
        $name = self::canonicalName($a);
        if ($name !== '' && $name === self::canonicalName($b)) {
            $messages->appendMessage(new Message(
                gettext('This name is already used. Names are compared case-insensitive and with surrounding spaces trimmed.'),
                $b->__reference . '.name'
            ));
        }

        $protocol = self::conflictingProtocol($a, $b);
        if ($protocol !== null) {
            $other = (string)$a->name !== ''
                ? sprintf(gettext('"%s"'), (string)$a->name)
                : gettext('another entry');
            $messages->appendMessage(new Message(
                sprintf(
                    gettext('This entry would reflect %s between the same interfaces as %s, for overlapping ' .
                            'devices and address families, so each packet would be reflected twice.'),
                    $protocol,
                    $other
                ),
                $b->__reference . '.source_if'
            ));
        }
    }

    /** The protocol both entries would reflect for the same traffic, or null. */
    private static function conflictingProtocol($a, $b)
    {
        if (
            (string)$a->source_if !== (string)$b->source_if ||
            (string)$a->target_if !== (string)$b->target_if
        ) {
            return null;
        }
        if (!self::macsOverlap((string)$a->macs, (string)$b->macs)) {
            return null;
        }
        if (!self::familiesOverlap((string)$a->address_family, (string)$b->address_family)) {
            return null;
        }

        if (
            (string)$a->wol === '1' && (string)$b->wol === '1' &&
            self::portsOverlap((string)$a->wol_ports, (string)$b->wol_ports)
        ) {
            return gettext('Wake-on-LAN');
        }
        if ((string)$a->mdns === '1' && (string)$b->mdns === '1') {
            return gettext('mDNS');
        }
        if ((string)$a->ssdp === '1' && (string)$b->ssdp === '1') {
            return gettext('SSDP');
        }
        if ((string)$a->wsd === '1' && (string)$b->wsd === '1') {
            return gettext('WS-Discovery');
        }

        return null;
    }

    /**
     * An empty port list is not "no ports": the daemon falls back to 7 and 9, so two entries that both
     * leave it blank do overlap. The opposite of macsOverlap, where empty widens the selection rather
     * than defaulting it.
     */
    private static function portsOverlap($a, $b)
    {
        $set_a = self::toSet($a) ?: self::DEFAULT_WOL_PORTS;
        $set_b = self::toSet($b) ?: self::DEFAULT_WOL_PORTS;
        return count(array_intersect($set_a, $set_b)) > 0;
    }

    /** An empty MAC selection means the whole network, which overlaps with any other selection. */
    private static function macsOverlap($a, $b)
    {
        $set_a = self::toSet($a);
        $set_b = self::toSet($b);
        if (empty($set_a) || empty($set_b)) {
            return true;
        }
        return count(array_intersect($set_a, $set_b)) > 0;
    }

    /** Families overlap when they both carry the same IP version. */
    private static function familiesOverlap($a, $b)
    {
        return (self::usesIpv4($a) && self::usesIpv4($b)) || (self::usesIpv6($a) && self::usesIpv6($b));
    }

    private static function usesIpv4($family)
    {
        return in_array($family, self::IPV4_FAMILIES, true);
    }

    private static function usesIpv6($family)
    {
        return in_array($family, self::IPV6_FAMILIES, true);
    }

    private static function canonicalName($entry)
    {
        return strtolower(trim((string)$entry->name));
    }

    /** A comma-separated field as a set of trimmed, lowercased values, empties dropped. */
    private static function toSet($csv)
    {
        $out = [];
        foreach (explode(',', $csv) as $value) {
            $value = strtolower(trim($value));
            if ($value !== '') {
                $out[] = $value;
            }
        }
        return $out;
    }
}
