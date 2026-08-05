package com.netpath.lab

import android.app.Application
import com.netpath.lab.config.ProfileStore
import com.netpath.lab.log.SessionLog

class NetPathApp : Application() {
    lateinit var profileStore: ProfileStore
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        profileStore = ProfileStore(this)
        SessionLog.append("NetPath Lab started — authorized security testing only")
    }

    companion object {
        lateinit var instance: NetPathApp
            private set
    }
}
