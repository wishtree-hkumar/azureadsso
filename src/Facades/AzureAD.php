<?php

namespace Wishtreehkumar\Azureadsso\Facades;

use Illuminate\Support\Facades\Facade;

class AzureAD extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'azure_ad';
    }
}