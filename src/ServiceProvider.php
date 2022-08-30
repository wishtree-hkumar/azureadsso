<?php

namespace Wishtreehkumar\Azureadsso;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind('azure_ad',function(){
            return new AzureAD;
        });

        $this->mergeConfigFrom(
            __DIR__.'/../config/azure.php', 'azure'
        );
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/azure.php' => config_path('azure.php'),
        ], 'config');
    }
}
