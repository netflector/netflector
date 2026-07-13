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

namespace OPNsense\Netflector\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\Netflector\Netflector;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Netflector\Netflector';
    protected static $internalServiceTemplate = 'OPNsense/Netflector';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'netflector';

    /**
     * Refuse to apply a configuration that is switched on with nothing to reflect.
     *
     * The model rejects that state too, but the grid's toggle reaches around it: OPNsense's
     * toggleBase() saves with `$disable_validation = true`, on purpose, so a toggle is never blocked by
     * validation. Unchecking the last reflector therefore lands in the saved model regardless, and
     * without this the GUI would go on showing "Enabled" over a daemon that is quietly not running,
     * because the daemon cannot start with no reflector at all. Apply is the last gate that sees every
     * path, so it is where this has to be caught.
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost() && !$this->serviceEnabled()) {
            $model = new Netflector();
            if ((string)$model->general->enabled === '1') {
                throw new UserException(
                    gettext(
                        'Enable at least one reflector, or switch Netflector off. ' .
                        'It cannot run with nothing to reflect.'
                    ),
                    gettext('Netflector')
                );
            }
        }

        return parent::reconfigureAction();
    }

    /**
     * The base class reads a single model path, but the daemon refuses to start with no reflector to
     * run. "Enabled" therefore has to mean the same thing here as in netflector_enabled() and in the
     * rc.conf.d template: the service switch is on AND at least one entry is on. Without this override
     * Apply would try to start a daemon whose generated configuration has no reflectors at all.
     */
    protected function serviceEnabled()
    {
        $model = new Netflector();

        if ((string)$model->general->enabled !== '1') {
            return false;
        }
        foreach ($model->reflectors->reflector->iterateItems() as $entry) {
            if ((string)$entry->enabled === '1') {
                return true;
            }
        }

        return false;
    }

    /**
     * Ask the daemon itself whether the generated configuration is valid (netflector --check-config).
     * The model's rules mirror the daemon's, but a mirror can drift; this is the authority, and it runs
     * against the file that will actually be loaded.
     */
    public function checkAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => gettext('This endpoint expects a POST.')];
        }

        // The action renders the configuration into a throwaway root and validates that, so it reports on
        // what would be applied without rewriting the file a restart would load. Regenerating the live
        // file here instead would mean a failed validation left the daemon unable to come back up.
        //
        // It answers as JSON with three states, because "valid", "invalid" and "nothing is enabled" are
        // genuinely different answers and only the middle one is a problem.
        $backend = new Backend();
        $output = trim($backend->configdRun('netflector check'));

        $result = json_decode($output, true);
        if (!is_array($result) || !isset($result['status'])) {
            return [
                'status' => 'failed',
                'message' => $output !== '' ? $output : gettext('The validation returned nothing.'),
            ];
        }

        return $result;
    }
}
