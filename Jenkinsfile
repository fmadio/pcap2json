pipeline {
	agent { docker { image 'pcap2json-docker' } }
	stages {
		stage('build') {
			steps {
				sh 'gcc --version'
			}
		}
	}
}
